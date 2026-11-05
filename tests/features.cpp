#include "../src/shared.hpp"
#include "../src/frames.hpp"
#include "../src/history.hpp"
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
        receipt << "S_OK_presents=" << succeeded << " observed=" << fs::read(shared->frameCount) << '\n'; receipt.flush();
        check(succeeded && fs::read(shared->frameCount) > 0 && fs::read(shared->frameSource) == 1, "real DXGI ETW Present signals");
        auto before = fs::read(shared->frameCount);
        for (unsigned i = 0; i < 25; ++i) chain->Present(0, DXGI_PRESENT_TEST);
        Sleep(1500);
        check(fs::read(shared->frameCount) == before, "DXGI test-only presents excluded");
        shared->frameSource = 2;
        for (unsigned i = 0; i < 25; ++i) chain->Present(0, 0);
        Sleep(1500);
        check(fs::read(shared->frameCount) == before, "native frame adapter not overwritten by ETW");
        context->Release(); device->Release(); chain->Release(); DestroyWindow(window);
        std::cout << "PASS: real DXGI Present ETW, test exclusion, adapter precedence. Evidence: " << folder.string() << '\n';
        return 0;
    }
    fs::History history(10000);
    fs::FrameGate frameGate;
    check(!frameGate.sample(1000, 900, 10, true, true, false, 2000), "frame monitor arms after progress");
    check(!frameGate.sample(1500, 1400, 11, true, true, false, 2000), "healthy frames");
    check(frameGate.sample(4000, 1400, 11, true, true, false, 2000), "frame silence with queue progress detected");
    check(!frameGate.sample(5000, 1400, 11, true, true, false, 2000), "one frame incident per stall");
    check(!frameGate.sample(6000, 5900, 12, true, true, false, 2000), "frame recovery rearms");
    check(frameGate.sample(9000, 5900, 12, true, true, false, 2000), "second independent frame incident");
    check(!frameGate.sample(20000, 5900, 12, true, true, true, 2000), "loading suppresses frame capture");
    check(!frameGate.sample(20001, 5900, 12, true, false, false, 2000), "background frames not assumed stalled");
    check(!frameGate.sample(22000, 5900, 12, true, true, false, 2000), "focus resume requires fresh presentation");
    check(!frameGate.sample(25000, 5900, 12, true, true, false, 2000), "stale background sample cannot arm");
    check(!frameGate.sample(30000, 29000, 15, false, true, false, 2000), "unavailable ETW never triggers frame capture");
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
