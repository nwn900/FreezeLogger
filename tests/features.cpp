#include "../src/shared.hpp"
#include "../src/frames.hpp"
#include "../src/history.hpp"
#include "../src/runtime.hpp"
#include <d3d11.h>
#include <dxgi.h>
#include <dbghelp.h>
#include <fstream>
#include <iostream>
#include <vector>

namespace {
void check(bool ok, const char* message) {
    if (!ok) { std::cerr << "FAIL: " << message << '\n'; ExitProcess(1); }
}
void write(const std::filesystem::path& path, size_t bytes) {
    std::ofstream out(path, std::ios::binary); std::string data(bytes, 'X'); out.write(data.data(), data.size());
}
}
int wmain(int argc, wchar_t** argv) {
    auto folder = std::filesystem::current_path() / ("feature-evidence-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(folder);
    auto shared = std::make_unique<fs::Shared>(); shared->pid = GetCurrentProcessId();
    {
        fs::FrameSignal native, etw;
        for (int i = 0; i < 10; ++i) check(etw.publish(900, 905, 2), "ETW frame publication");
        auto etwSample = etw.snapshot();
        check(etwSample.status == fs::FrameReadStatus::Coherent && etwSample.sample.present &&
              etwSample.sample.count == 10 && etwSample.sample.tick == 900, "coherent ETW frame snapshot");
        fs::FrameProviderSelector selector;
        auto selection = selector.select(native.snapshot(), etwSample, true, 1000);
        check(selection.source == 1 && selection.sample.tick == 900, "ETW fallback selected when native adapter is absent");
        check(native.publish(1000, 1000, 3), "native frame publication");
        selection = selector.select(native.snapshot(), etw.snapshot(), true, 1000);
        check(selection.source == 2 && selection.sample.tick == 1000, "native frame source outranks delayed ETW");
        selection = selector.select(native.snapshot(), etw.snapshot(), true,
                                    1000 + fs::FrameProviderSelector::nativeFreshnessMs + 1);
        check(selection.source == 1 && selection.nativeExpired, "stale native source expires and ETW resumes");
        check(native.publish(5000, 5000, 3), "native frame republication");
        selection = selector.select(native.snapshot(), etw.snapshot(), true, 5000);
        check(selection.source == 2 && !selection.nativeExpired, "resumed native source regains precedence");
        auto busy = fs::FrameReadResult{{}, fs::FrameReadStatus::Busy};
        fs::FrameProviderSelector etwBusySelector;
        fs::FrameSignal neverNative;
        selection = etwBusySelector.select(neverNative.snapshot(), etwSample, true, 1000);
        check(selection.source == 1, "ETW provider is available before a native source publishes");
        selection = etwBusySelector.select(neverNative.snapshot(), busy, true, 1000);
        check(selection.source == 1 && selection.sample.tick == 900,
              "a busy ETW read retains its last coherent fallback sample");
        fs::FrameSignal busyNative;
        check(busyNative.publish(5000, 5000, 3), "busy fixture native publication");
        fs::FrameProviderSelector busySelector;
        selection = busySelector.select(busy, etwSample, true, 5000);
        check(selection.source == 0, "a busy first native publication is not mistaken for absent native telemetry");
        selection = busySelector.select(busyNative.snapshot(), etw.snapshot(), true, 5000);
        check(selection.source == 2, "coherent native publication becomes authoritative");
        selection = busySelector.select(busy, etw.snapshot(), true, 5000);
        check(selection.source == 2 && selection.sample.tick == 5000,
              "a busy native read retains its last coherent sample and native authority");
        selection = busySelector.select(busy, etw.snapshot(), true,
                                        5000 + fs::FrameProviderSelector::nativeFreshnessMs + 1);
        check(selection.source == 1 && selection.nativeExpired,
              "a busy native read after the freshness window falls back to ETW");

        // Both sources genuinely frozen: the handover keeps the last present
        // time, so the gate still reports a stall instead of a healthy handover.
        fs::FrameSignal frozenNative, frozenEtw;
        for (int i = 0; i < 10; ++i) {
            check(frozenNative.publish(1000, 1000, 3) && frozenEtw.publish(1000, 1000, 2), "frozen fixture publication");
        }
        fs::FrameProviderSelector frozenSelector;
        auto frozen = frozenSelector.select(frozenNative.snapshot(), frozenEtw.snapshot(), true, 1000);
        check(frozen.source == 2, "frozen fixture starts on native");
        fs::FrameGate gate;
        check(!gate.sample(1000, frozen, true, false, 2000), "frozen fixture gate arms");
        frozen = frozenSelector.select(frozenNative.snapshot(), frozenEtw.snapshot(), true, 4000);
        check(frozen.source == 1 && frozen.sample.tick == 1000, "frozen native hands over to frozen ETW");
        check(!gate.sample(4000, frozen, true, false, 2000), "handover rebases without a spurious immediate report");
        check(gate.sample(4001, frozen, true, false, 2000), "handover to an equally frozen source still reports the stall");

        // Native-only stall: ETW is unavailable, so the last native sample must
        // stay as stalled evidence instead of resetting the gate.
        fs::FrameSignal nativeOnly;
        for (int i = 0; i < 10; ++i) check(nativeOnly.publish(1000, 1000, 3), "native-only fixture publication");
        fs::FrameProviderSelector nativeOnlySelector;
        auto nativeOnlySample = nativeOnlySelector.select(nativeOnly.snapshot(), {}, false, 1000);
        check(nativeOnlySample.source == 2, "native-only source selected while fresh");
        fs::FrameGate nativeOnlyGate;
        check(!nativeOnlyGate.sample(1000, nativeOnlySample, true, false, 15000), "native-only gate arms");
        auto staleNative = nativeOnlySelector.select(nativeOnly.snapshot(), {}, false, 3001);
        check(staleNative.source == 2 && staleNative.nativeExpired,
              "stale native sample is retained as evidence when ETW is unavailable");
        check(!nativeOnlyGate.sample(3001, staleNative, true, false, 15000),
              "stale native sample does not reset the gate");
        check(nativeOnlyGate.sample(16001, staleNative, true, false, 15000),
              "native-only stall is reported after the configured timeout");
        check(!nativeOnlyGate.sample(17000, staleNative, true, false, 15000),
              "native-only stall is reported once");
        check(nativeOnly.publish(18000, 18000, 3), "native-only recovery publication");
        auto recovered = nativeOnlySelector.select(nativeOnly.snapshot(), {}, false, 18000);
        check(recovered.source == 2 && !recovered.nativeExpired, "returning native source is fresh again");
        check(!nativeOnlyGate.sample(18000, recovered, true, false, 15000), "recovery rearms the gate");
        check(nativeOnlyGate.sample(34000, recovered, true, false, 15000),
              "second native-only stall is reported after recovery");
        fs::FrameGate slowGate;
        check(!slowGate.sample(1000, nativeOnlySample, true, false, 30000), "slow gate arms");
        check(!slowGate.sample(20000, staleNative, true, false, 30000), "slow gate waits for its 30 s timeout");
        check(slowGate.sample(31001, staleNative, true, false, 30000), "slow gate reports at 30 s");
        fs::FrameProviderSelector emptySelector;
        check(emptySelector.select({}, {}, false, 5000).source == 0,
              "both sources absent from the start stays unavailable");

        // ETW with an insufficient sample count is not an eligible fallback: an
        // armed native gate must keep its qualified native evidence.
        for (LONG etwCount : {1L, 9L}) {
            fs::FrameSignal qualifiedNative, thinEtw;
            for (int i = 0; i < 10; ++i) check(qualifiedNative.publish(1000, 1000, 3), "qualified native publication");
            for (LONG i = 0; i < etwCount; ++i) check(thinEtw.publish(1000, 1000, 2), "thin ETW publication");
            fs::FrameProviderSelector thinSelector;
            auto fresh = thinSelector.select(qualifiedNative.snapshot(), thinEtw.snapshot(), true, 1000);
            check(fresh.source == 2 && fresh.usable, "qualified native wins while fresh");
            fs::FrameGate thinGate;
            check(!thinGate.sample(1000, fresh, true, false, 15000), "qualified native gate arms");
            auto stale = thinSelector.select(qualifiedNative.snapshot(), thinEtw.snapshot(), true, 3001);
            check(stale.source == 2 && stale.nativeExpired && stale.usable,
                  "thin ETW is not an eligible fallback; qualified native evidence is retained");
            check(!thinGate.sample(3001, stale, true, false, 15000), "thin ETW does not reset the gate");
            check(thinGate.sample(16001, stale, true, false, 15000), "native stall still reports with thin ETW present");
        }
        // A qualified ETW fallback (>=10 frames) is eligible and hands over.
        {
            fs::FrameSignal qualifiedNative, qualifiedEtw;
            for (int i = 0; i < 10; ++i) check(qualifiedNative.publish(1000, 1000, 3), "qualified native publication");
            for (int i = 0; i < 10; ++i) check(qualifiedEtw.publish(1000, 1000, 2), "qualified ETW publication");
            fs::FrameProviderSelector qualifiedSelector;
            auto fresh = qualifiedSelector.select(qualifiedNative.snapshot(), qualifiedEtw.snapshot(), true, 1000);
            check(fresh.source == 2, "qualified native wins while fresh");
            auto handoff = qualifiedSelector.select(qualifiedNative.snapshot(), qualifiedEtw.snapshot(), true, 3001);
            check(handoff.source == 1 && handoff.nativeExpired && handoff.usable,
                  "qualified ETW is an eligible fallback");
            fs::FrameGate qualifiedGate;
            check(!qualifiedGate.sample(1000, fresh, true, false, 15000), "gate arms on native");
            check(!qualifiedGate.sample(3001, handoff, true, false, 15000), "handover rebases on ETW's own tick");
            check(qualifiedGate.sample(16001, handoff, true, false, 15000), "both-frozen stall reports after handover");
        }
        // ETW Busy with an insufficient count is not eligible either.
        {
            fs::FrameSignal qualifiedNative, thinEtw;
            for (int i = 0; i < 10; ++i) check(qualifiedNative.publish(1000, 1000, 3), "qualified native publication");
            check(thinEtw.publish(1000, 1000, 2), "thin ETW publication");
            fs::FrameProviderSelector busyThinSelector;
            (void)busyThinSelector.select(qualifiedNative.snapshot(), thinEtw.snapshot(), true, 1000);
            auto busyThin = fs::FrameReadResult{{}, fs::FrameReadStatus::Busy};
            auto stale = busyThinSelector.select(qualifiedNative.snapshot(), busyThin, true, 3001);
            check(stale.source == 2 && stale.nativeExpired,
                  "busy thin ETW does not replace qualified native evidence");
        }
        // ETW once qualified then stopped: the last ETW sample stays as evidence.
        {
            fs::FrameSignal qualifiedNative, qualifiedEtw;
            for (int i = 0; i < 10; ++i) check(qualifiedNative.publish(1000, 1000, 3), "qualified native publication");
            for (int i = 0; i < 10; ++i) check(qualifiedEtw.publish(1000, 1000, 2), "qualified ETW publication");
            fs::FrameProviderSelector stoppedSelector;
            (void)stoppedSelector.select(qualifiedNative.snapshot(), qualifiedEtw.snapshot(), true, 1000);
            auto handoff = stoppedSelector.select(qualifiedNative.snapshot(), qualifiedEtw.snapshot(), true, 3001);
            check(handoff.source == 1 && handoff.usable, "ETW handoff uses its last qualified sample");
            auto later = stoppedSelector.select(qualifiedNative.snapshot(), qualifiedEtw.snapshot(), true, 20000);
            check(later.source == 1 && later.sample.tick == 1000, "stopped ETW keeps its last present time");
        }
        // Handover must not backdate progress: native presented at 20 s, a
        // once-qualified ETW is stalled at 1 s. The gate must wait a full
        // timeout from the newer progress, not fire immediately.
        auto handoverFrame = [](LONG source, LONG64 tick, LONG64 count) {
            fs::FrameSnapshot sample{tick, tick, count, 1, count != 0};
            return fs::FrameSelection{sample, source};
        };
        {
            fs::FrameGate progressGate;
            auto nativeProgress = handoverFrame(2, 20000, 100);
            auto staleEtw = handoverFrame(1, 1000, 50);
            check(!progressGate.sample(20000, nativeProgress, true, false, 15000), "native progress arms");
            check(!progressGate.sample(22001, staleEtw, true, false, 15000),
                  "stale ETW handover does not backdate progress");
            check(!progressGate.sample(22201, staleEtw, true, false, 15000),
                  "no false report before the threshold");
            check(!progressGate.sample(34999, staleEtw, true, false, 15000), "still below the threshold");
            check(progressGate.sample(35000, staleEtw, true, false, 15000), "reports once at the threshold");
            check(!progressGate.sample(35200, staleEtw, true, false, 15000), "no duplicate report");
        }
        // Reverse: the fallback is newer than the native sample.
        {
            fs::FrameGate reverseGate;
            auto staleNativeSample = handoverFrame(2, 1000, 100);
            auto freshEtw = handoverFrame(1, 20000, 50);
            check(!reverseGate.sample(20000, staleNativeSample, true, false, 15000), "stale native arms");
            check(!reverseGate.sample(22001, freshEtw, true, false, 15000), "fresh ETW handover adopts newer progress");
            check(!reverseGate.sample(34999, freshEtw, true, false, 15000), "fresh ETW progress is not backdated");
            check(reverseGate.sample(35000, freshEtw, true, false, 15000),
                  "stall reports at the threshold from the newer progress");
        }
        // Equal-tick both-frozen handover still reports at the threshold.
        {
            fs::FrameGate equalGate;
            auto frozenA = handoverFrame(2, 1000, 100);
            auto frozenB = handoverFrame(1, 1000, 50);
            check(!equalGate.sample(1000, frozenA, true, false, 15000), "frozen native arms");
            check(!equalGate.sample(3001, frozenB, true, false, 15000), "equal-tick handover does not report immediately");
            check(equalGate.sample(16001, frozenB, true, false, 15000), "equal-tick both-frozen reports at the threshold");
            check(!equalGate.sample(17000, handoverFrame(1, 16900, 51), true, false, 15000), "ETW recovery rearms");
            check(equalGate.sample(32000, handoverFrame(1, 16900, 51), true, false, 15000), "second stall reports after recovery");
        }
        // A 30 s deadline uses the same preserved progress.
        {
            fs::FrameGate slowProgressGate;
            auto nativeProgress = handoverFrame(2, 20000, 100);
            auto staleEtw = handoverFrame(1, 1000, 50);
            check(!slowProgressGate.sample(20000, nativeProgress, true, false, 30000), "slow gate arms");
            check(!slowProgressGate.sample(22001, staleEtw, true, false, 30000), "slow handover preserves progress");
            check(!slowProgressGate.sample(49999, staleEtw, true, false, 30000), "slow gate waits for 30 s");
            check(slowProgressGate.sample(50000, staleEtw, true, false, 30000), "slow gate reports at 30 s");
        }
        LONG64 eventTick = 0;
        check(fs::frameTickFromQpc(100000, 200000, 1000000, 10000, eventTick) && eventTick == 9900,
              "ETW presentation timestamp maps from QPC to monotonic milliseconds");
        check(!fs::frameTickFromQpc(200000, 100000, 1000000, 10000, eventTick),
              "future or invalid raw QPC timestamps are rejected");
    }
    {
        std::string diagnostic = fs::utf8(L"\u017c\u00f3\u0142\u0107\t\"\\\x01");
        std::string escaped = fs::jsonEscape(diagnostic);
        check(escaped.find("\xC5\xBC\xC3\xB3\xC5\x82\xC4\x87") != std::string::npos && escaped.find("\\t") != std::string::npos &&
              escaped.find("\\\"") != std::string::npos && escaped.find("\\\\") != std::string::npos &&
              escaped.find("\\u0001") != std::string::npos,
              "UTF-8 diagnostic paths and JSON control escaping remain valid");
        std::wstring invalidUtf16(1, static_cast<wchar_t>(0xd800));
        check(fs::diagnosticUtf8(invalidUtf16) == "<text-encoding-error>",
              "invalid UTF-16 diagnostic text cannot abort report capture");
    }
    check(fs::RuntimeModuleClassifier::isVictimLocation("f4se_1_10_163.dll") &&
          fs::RuntimeModuleClassifier::isF4seRuntime("f4sevr_1_2_72.dll"),
          "versioned F4SE runtime modules are recognized");
    check(!fs::RuntimeModuleClassifier::isF4seRuntime("f4se_1__163.dll") &&
          !fs::RuntimeModuleClassifier::isF4seRuntime("f4se_custom.dll"),
          "malformed F4SE runtime names are not classified as versioned runtimes");
    if (argc == 2 && std::wstring(argv[1]) == L"--frames") {
        fs::FrameObserver observer(shared.get());
        auto error = observer.start();
        std::ofstream receipt(folder / "etw.log"); receipt << "start_status=" << error << '\n'; receipt.flush();
        if (error) {
            std::cout << "ETW unavailable, code=" << error << "; queue fallback remains active. Evidence: " << folder.string() << '\n';
            return 77;
        }
        HWND window = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, L"STATIC", L"FreezeSentry DXGI fixture", WS_POPUP | WS_VISIBLE,
            -32000, -32000, 32, 32, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        check(window != nullptr, "DXGI fixture window");
        DXGI_SWAP_CHAIN_DESC description{};
        description.BufferDesc.Width = description.BufferDesc.Height = 32; description.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        description.SampleDesc.Count = 1; description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        description.BufferCount = 1; description.OutputWindow = window; description.Windowed = TRUE;
        IDXGISwapChain* chain = nullptr; ID3D11Device* device = nullptr; ID3D11DeviceContext* context = nullptr;
        HRESULT result = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, nullptr, 0,
            D3D11_SDK_VERSION, &description, &chain, &device, nullptr, &context);
        check(SUCCEEDED(result), "real WARP DXGI swap chain");
        unsigned succeeded = 0;
        auto deadline = fs::now() + 4000;
        while (fs::now() < deadline) { if (chain->Present(0, 0) == S_OK) ++succeeded; Sleep(20); }
        Sleep(1500);
        auto observed = observer.current();
        receipt << "S_OK_presents=" << succeeded << " observed=" << observed.sample.count << '\n'; receipt.flush();
        check(succeeded && observed.sample.count > 0 && observed.source == 1, "real DXGI ETW Present signals");
        auto before = fs::read(shared->frameCount);
        for (unsigned i = 0; i < 25; ++i) chain->Present(0, DXGI_PRESENT_TEST);
        Sleep(1500);
        observer.current();
        check(fs::read(shared->frameCount) == before, "DXGI test-only presents excluded");
        check(shared->nativeFrames.publish(fs::now(), fs::now(), GetCurrentThreadId()), "native adapter frame fixture");
        for (unsigned i = 0; i < 25; ++i) chain->Present(0, 0);
        Sleep(1500);
        auto selected = observer.current();
        check(selected.source == 2 && selected.sample.count == 1 && fs::read(shared->frameCount) == 1,
              "native frame adapter not overwritten by ETW");
        context->Release(); device->Release(); chain->Release(); DestroyWindow(window);
        std::cout << "PASS: real DXGI Present ETW, test exclusion, adapter precedence. Evidence: " << folder.string() << '\n';
        return 0;
    }
    check(fs::sessionId(42, 1000) == L"42-1000" && fs::sessionId(42, 2000) != fs::sessionId(42, 1000),
          "session identity includes the process creation time");
    fs::History history(10000);
    fs::FrameGate frameGate;
    auto frame = [](LONG source, LONG64 tick, LONG64 count) {
        fs::FrameSnapshot sample{tick, tick, count, 1, count != 0};
        return fs::FrameSelection{sample, source};
    };
    check(!frameGate.sample(1000, frame(1, 900, 10), true, false, 2000), "frame monitor arms after eligibility");
    check(!frameGate.sample(1500, frame(1, 1400, 11), true, false, 2000), "healthy frames");
    check(frameGate.sample(4000, frame(1, 1400, 11), true, false, 2000), "frame silence with queue progress detected");
    check(!frameGate.sample(5000, frame(1, 1400, 11), true, false, 2000), "one frame incident per stall");
    check(!frameGate.sample(6000, frame(1, 5900, 12), true, false, 2000), "frame recovery rearms");
    check(frameGate.sample(9000, frame(1, 5900, 12), true, false, 2000), "second independent frame incident");
    check(!frameGate.sample(20000, frame(1, 5900, 12), true, true, 2000), "loading suppresses frame capture");
    check(!frameGate.sample(20001, frame(1, 5900, 12), false, false, 2000), "background frames not assumed stalled");
    check(!frameGate.sample(22000, frame(1, 5900, 12), true, false, 2000), "focus resume establishes a fresh deadline");
    check(frameGate.sample(24000, frame(1, 5900, 12), true, false, 2000), "no fresh foreground presentation times out");
    check(!frameGate.sample(30000, frame(0, 29000, 15), true, false, 2000), "unavailable ETW never triggers frame capture");
    fs::FrameGate bufferedFrameGate;
    check(!bufferedFrameGate.sample(8000, frame(1, 8000, 20), false, false, 2000), "background frame progress is ineligible");
    check(!bufferedFrameGate.sample(10000, frame(1, 8000, 20), true, false, 2000), "foreground resume establishes a new eligibility baseline");
    check(!bufferedFrameGate.sample(10200, frame(1, 8100, 21), true, false, 2000),
          "buffered pre-resume presentation cannot trigger or rearm foreground monitoring");
    check(bufferedFrameGate.sample(12000, frame(1, 8100, 21), true, false, 2000),
          "frame silence is detected after the foreground eligibility timeout");
    fs::FrameGate handoverGate;
    check(!handoverGate.sample(1000, frame(1, 900, 100000), true, false, 2000), "ETW provider arms the frame gate");
    check(!handoverGate.sample(1100, frame(1, 1050, 100001), true, false, 2000), "ETW progress advances its own counter");
    check(!handoverGate.sample(1200, frame(2, 1190, 11), true, false, 2000), "native provider handover rebases source identity and count");
    check(!handoverGate.sample(1210, frame(2, 1205, 12), true, false, 2000), "native progress advances after handover");
    check(handoverGate.sample(3210, frame(2, 1205, 12), true, false, 2000),
          "native stall is detected after handover despite its lower source counter");
    fs::FrameGate interleavedClockGate;
    check(!interleavedClockGate.sample(1000, frame(1, 900, 10), true, false, 2000),
          "interleaved-clock frame gate arms");
    check(!interleavedClockGate.sample(3000, frame(1, 3001, 11), true, false, 2000),
          "future frame timestamp is deferred without consuming its counter");
    check(!interleavedClockGate.sample(3002, frame(1, 3001, 11), true, false, 2000),
          "same frame is credited when the post-snapshot clock catches up");
    check(interleavedClockGate.sample(5003, frame(1, 3001, 11), true, false, 2000),
          "frame silence is detected after the credited interleaved frame");
    for (unsigned i = 0; i < 100; ++i) history.add(std::string(65536, 'x'));
    check(history.text().size() < 2 * 1024 * 1024 + 1024, "history bounded to 2 MiB");
    history.clear(); check(history.text().find("samples=0") != std::string::npos, "history reset");
    auto before = folder / "freeze-20261008-010000-000-1.log";
    auto latest = folder / "freeze-20261008-020000-000-1.log";
    auto dump = before; dump.replace_extension(".dmp");
    auto user = folder / "user-notes.log";
    auto active = folder / "session-1.log";
    write(before, 200); write(dump, 2 * 1024 * 1024); write(user, 10); write(active, 300); write(latest, 200);
    std::filesystem::last_write_time(before, std::filesystem::file_time_type::clock::now() - std::chrono::hours(2));
    fs::retain(folder, 10, 10, 1, active);
    check(!std::filesystem::exists(dump) && std::filesystem::exists(before) && std::filesystem::exists(latest), "quota removes dumps before text");
    check(std::filesystem::exists(user) && std::filesystem::exists(active), "quota protects unrelated and active files");
    fs::retain(folder, 1, 1);
    check(!std::filesystem::exists(before) && std::filesystem::exists(latest), "count retention");
    auto manualOld = folder / "manual-20261008-003000-000-1.log";
    auto manualNew = folder / "manual-20261008-004000-000-1.log";
    write(manualOld, 100); write(manualNew, 100);
    std::filesystem::last_write_time(manualOld, std::filesystem::file_time_type::clock::now() - std::chrono::hours(2));
    fs::retain(folder, 1, 1);
    check(std::filesystem::exists(manualNew) && std::filesystem::exists(latest), "categories keep their own newest pair");
    fs::retain(folder, 10, 1);
    check(!std::filesystem::exists(manualOld) && std::filesystem::exists(manualNew), "manual cap prunes independently");
    auto partial = folder / "freeze-20261008-030000-000-1.dmp.partial";
    write(partial, 100);
    std::filesystem::last_write_time(partial, std::filesystem::file_time_type::clock::now() - std::chrono::hours(2));
    fs::retain(folder, 1, 1);
    check(!std::filesystem::exists(partial), "stale partial cleanup");
    auto otherSession = folder / "session-777.log";
    auto otherHistory = folder / "prehang-777.log";
    auto otherIncident = folder / "freeze-20261008-050000-000-777.log";
    auto otherDump = otherIncident; otherDump.replace_extension(".dmp");
    write(otherSession, 100); write(otherHistory, 100); write(otherIncident, 100); write(otherDump, 2 * 1024 * 1024);
    // Older than this collector's incident: count pruning must not erase its protection before quota pruning.
    std::filesystem::last_write_time(otherIncident, std::filesystem::file_time_type::clock::now() - std::chrono::hours(3));
    {
        fs::Handle lease(CreateFileW(otherSession.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        check(lease.value != INVALID_HANDLE_VALUE, "second collector session lease");
        fs::retain(folder, 1, 1, 1, active);
        check(std::filesystem::exists(otherHistory) && std::filesystem::exists(otherIncident) && std::filesystem::exists(otherDump),
              "another live collector history and capture protected");
    }

    // A newer freeze for an active PID supersedes its older manual report as
    // the protected live incident, allowing the older manual record to satisfy
    // a total-storage quota.
    auto activeAudit = folder / "live-retention-audit";
    std::filesystem::create_directories(activeAudit);
    auto activeSession = activeAudit / "session-987.log";
    auto oldManual = activeAudit / "manual-20261008-010000-000-987.log";
    auto newFreeze = activeAudit / "freeze-20261008-020000-000-987.log";
    write(activeSession, 16); write(oldManual, 2 * 1024 * 1024); write(newFreeze, 16);
    std::filesystem::last_write_time(oldManual, std::filesystem::file_time_type::clock::now() - std::chrono::hours(2));
    std::filesystem::last_write_time(newFreeze, std::filesystem::file_time_type::clock::now() - std::chrono::hours(1));
    auto activePartial = activeAudit / "prehang-987.log.partial";
    write(activePartial, 128);
    {
        fs::Handle lease(CreateFileW(activeSession.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        check(lease.value != INVALID_HANDLE_VALUE, "live retention collector lease");
        fs::retain(activeAudit, 10, 10, 1, activeSession);
        check(!std::filesystem::exists(oldManual) && std::filesystem::exists(newFreeze),
              "quota prunes older active manual report but preserves newer freeze");
        check(std::filesystem::exists(activePartial), "active prehang partial remains protected");
    }
    auto abandoned = activeAudit / "prehang-988.log.partial";
    write(abandoned, 64);
    std::filesystem::last_write_time(abandoned, std::filesystem::file_time_type::clock::now() - std::chrono::hours(2));
    fs::retain(activeAudit, 10, 10);
    check(!std::filesystem::exists(abandoned), "abandoned prehang partial participates in stale cleanup");
    fs::retain(folder, 1, 1, 1, active);
    check(!std::filesystem::exists(otherDump), "completed collector dump becomes eligible for quota");
    auto link = folder / "freeze-20261008-040000-000-1.dmp";
    std::error_code linkError; std::filesystem::create_symlink(user, link, linkError);
    if (!linkError) { fs::retain(folder, 1, 1, 1); check(std::filesystem::is_symlink(link), "retention skips symlinks"); }
    auto invalid = folder / "invalid.dmp";
    write(invalid, 4096); std::string reason;
    check(!fs::validateDump(invalid, reason), "invalid signature rejected");
    write(invalid, 8); check(!fs::validateDump(invalid, reason), "truncated header rejected");
    std::cout << "PASS: ring bounds, quota ordering, active protection, count retention, partial cleanup and bad dumps. Evidence: " << folder.string() << '\n';
}
