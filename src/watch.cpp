#include "shared.hpp"
#include "exceptions.hpp"
#include "suppress.hpp"
#include <shellapi.h>
#include <fstream>
#include <array>
#include <psapi.h>
#include <algorithm>
#include "history.hpp"
#include "frames.hpp"
#include "lifetime.hpp"
#include "context.hpp"
#include <sstream>

namespace {
struct Window { DWORD pid; HWND handle = nullptr; };
BOOL CALLBACK findWindow(HWND handle, LPARAM parameter) {
    auto& window = *reinterpret_cast<Window*>(parameter);
    DWORD pid = 0; GetWindowThreadProcessId(handle, &pid);
    if (pid == window.pid && IsWindowVisible(handle) && !GetWindow(handle, GW_OWNER)) {
        window.handle = handle; return FALSE;
    }
    return TRUE;
}
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 1;
    std::wstring mode = argc == 3 ? argv[1] : L"";
    wchar_t* end = nullptr;
    auto raw = argc == 3 ? wcstoull(argv[2], &end, 10) : 0;
    bool valid = argc == 3 && mode == L"--watch" && end != argv[2] && !*end && raw;
    LocalFree(argv);
    if (!valid) return 2;
    fs::Handle mapping(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(raw)));
    auto* state = static_cast<fs::Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(fs::Shared)));
    if (!state) return 3;
    struct Unmap { void* p; ~Unmap() { UnmapViewOfFile(p); } } unmap{state};
    if (state->signature != fs::magic || state->version != 7 || !state->pid ||
        state->timeoutMs < 2000 || state->timeoutMs > 3600000 ||
        state->loadingMs < 2000 || state->loadingMs > 3600000 ||
        state->startupMs < 2000 || state->startupMs > 3600000 ||
        !state->maxReports || state->maxReports > 100 || state->manualKey > 255 ||
        state->outputDirectory[1023] != 0 || state->historyMs < 10000 || state->historyMs > 120000 ||
        state->profileMs < 500 || state->profileMs > 10000 || state->earlyMs > 60000 ||
        state->storageMB > 65536 || state->frameMonitoring > 1 || state->contextMonitoring > 1 ||
        state->captureMs < 15000 || state->captureMs > 900000) return 4;
    fs::Handle target(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_PROCESS |
                                  PROCESS_DUP_HANDLE | SYNCHRONIZE, FALSE, state->pid));
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!target.value || !GetProcessTimes(target, &creation, &exit, &kernel, &user) ||
        fs::filetime(creation) != fs::read(state->processCreated)) return 5;
    try {
        fs::Lifetime lifetime(target, 30000, L"FreezeSentryF4-" + std::to_wstring(state->pid) + L"-" + std::to_wstring(fs::read(state->processCreated)));
        std::array<wchar_t, 32768> exe{};
        DWORD length = static_cast<DWORD>(exe.size());
        std::filesystem::path gameImage;
        DWORD gameImageQueryError = ERROR_SUCCESS;
        if (QueryFullProcessImageNameW(target, 0, exe.data(), &length) && length)
            gameImage = std::filesystem::path(std::wstring_view(exe.data(), length));
        else gameImageQueryError = GetLastError();
        auto image = gameImage.filename().wstring();
        bool vr = _wcsicmp(image.c_str(), L"Fallout4VR.exe") == 0;
        auto folder = state->outputDirectory[0] ? std::filesystem::path(state->outputDirectory) : fs::reportRoot(vr);
        std::filesystem::create_directories(folder);
        auto sessionPath = folder / ("session-" + std::to_string(state->pid) + ".log");
        auto historyPath = folder / ("prehang-" + std::to_string(state->pid) + ".log");
        std::ofstream session(sessionPath, std::ios::trunc);
        if (gameImageQueryError)
            session << "game_image_query_error=" << gameImageQueryError << "; external crash logs will not be attributed\n";
        session << "FreezeSentryF4 monitor started. PID=" << state->pid << " runtime=" << state->runtime
                << " task_monitoring=" << state->taskMonitoring << '\n';
        session.flush();
        if (!session) return 6;
        InterlockedExchange64(&state->monitorPulse, fs::now());
        fs::FrameObserver frames(state);
        auto frameStart = frames.start();
        if (frameStart) InterlockedExchange(&state->frameStatus, static_cast<LONG>(frameStart));
        session << "DXGI_ETW_status=" << fs::read(state->frameStatus) << " (nonzero: unavailable; no elevation requested)\n";
        session.flush();
        { // Startup compatibility snapshot: versions, thresholds and memory headroom in one machine-readable file.
            MEMORYSTATUSEX memory{};
            memory.dwLength = sizeof(memory);
            GlobalMemoryStatusEx(&memory);
            std::ofstream preflight(folder / ("preflight-" + std::to_string(state->pid) + ".json"), std::ios::trunc);
            preflight << "{\n"
                      << "  \"tool\": \"FreezeSentryF4 " << fs::toolVersion << "\",\n"
                      << "  \"shared_version\": 7,\n"
                      << "  \"game_image\": \"" << fs::jsonEscape(fs::diagnosticPath(gameImage)) << "\",\n"
                      << "  \"pid\": " << state->pid << ",\n"
                      << "  \"runtime\": " << state->runtime << ",\n"
                      << "  \"extender\": " << state->extender << ",\n"
                      << "  \"timeout_ms\": " << state->timeoutMs << ",\n"
                      << "  \"loading_ms\": " << state->loadingMs << ",\n"
                      << "  \"startup_ms\": " << state->startupMs << ",\n"
                      << "  \"task_monitoring\": " << state->taskMonitoring << ",\n"
                      << "  \"frame_monitoring\": " << state->frameMonitoring << ",\n"
                      << "  \"context_monitoring\": " << state->contextMonitoring << ",\n"
                      << "  \"suppress_background\": " << state->suppressBackground << ",\n"
                      << "  \"foreground_grace_sec\": " << state->foregroundGraceSec << ",\n"
                      << "  \"max_reports_legacy\": " << state->maxReports << ",\n"
                      << "  \"max_freeze_reports\": " << state->maxFreezeReports << ",\n"
                      << "  \"max_manual_reports\": " << state->maxManualReports << ",\n"
                      << "  \"output\": \"" << fs::jsonEscape(fs::diagnosticPath(folder)) << "\",\n"
                      << "  \"avail_phys_bytes\": " << memory.ullAvailPhys << ",\n"
                      << "  \"avail_commit_bytes\": " << memory.ullAvailPageFile << "\n"
                      << "}\n";
            preflight.flush();
            session << "preflight=" << (preflight ? "written" : "FAILED") << '\n';
            session.flush();
        }
        fs::History history(state->historyMs);
        fs::ExceptionJournal exceptionJournal(state);
        fs::ContextObserver context(target, state->runtime, state->contextMonitoring != 0);
        session << "context_adapter=" << context.qualification() << '\n'; session.flush();
        fs::EngineContext currentContext, lastContext;
        fs::EngineContext lastReadable;
        LONG64 lastCellTick = 0, lastMenusTick = 0;
        LONG64 contextTick = 0, lastContextPoll = 0;
        bool contextSeen = false;
        fs::FrameGate frameGate;
        LONG64 lastProfile = 0, lastEarly = 0, lastRetention = 0, lastPublished = 0;
        unsigned earlyCount = 0;
        bool profilePaused = true;
        auto contextEvidence = [&] {
            std::ostringstream evidence;
            evidence << "context_sample_tick=" << contextTick << '\n' << currentContext.text();
            if ((!currentContext.cellValid && lastCellTick) || (!currentContext.menusValid && lastMenusTick)) {
                evidence << "LAST_READABLE_CONTEXT (historical fields; do not assume they are still current)\n"
                    << "cell_tick=" << lastCellTick << " menus_tick=" << lastMenusTick << '\n' << lastReadable.text();
            }
            return evidence.str();
        };
        auto persistHistory = [&] {
            auto temporary = historyPath; temporary += ".partial";
            { std::ofstream out(temporary, std::ios::trunc); out << "PID=" << state->pid << " created=" << fs::read(state->processCreated)
                << '\n' << contextEvidence()
                << fs::eventHistory(state) << history.text(); out.flush();
                if (!out) { session << "prehang_write_failed\n"; session.flush(); return; } }
            if (!MoveFileExW(temporary.c_str(), historyPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                session << "prehang_commit_error=" << GetLastError() << '\n'; session.flush();
            }
        };
        fs::retain(folder, state->maxFreezeReports, state->maxManualReports, state->storageMB, sessionPath);
        fs::StallGate gate;
        fs::HangSuppressionPolicy suppression;
        bool suppressionLogged = false;
        LONG lastEvent = -2;
        LONG64 lastEventTime = -1, lastPoll = fs::now(), lastManual = 0;
        bool keyWasDown = false, wasReported = false;
        LONG64 windowPulse = 0;
        LONG64 inventoryTime = 0;
        std::array<HMODULE, 2048> previousModules{}; DWORD previousModuleBytes = 0;
        std::vector<fs::CrashModuleIdentity> processModules;
        auto collect = [&](const std::string& reason) {
            lifetime.budget(state->captureMs);
            session << "capture_started tick=" << fs::now() << " reason=" << reason << " collector_deadline_ms=" << state->captureMs
                    << " (exit 124=deadline; 125=target exited during blocked cleanup)\n";
            session.flush();
            try {
                bool complete = fs::capture(target, state->pid, folder, reason, state, state->writeDump != 0,
                    contextEvidence() + history.text());
                session << "tick=" << fs::now() << " incident=" << reason << " collection_complete=" << complete << '\n';
                fs::retain(folder, state->maxFreezeReports, state->maxManualReports, state->storageMB, sessionPath);
            } catch (const std::exception& error) {
                session << "capture failed: " << error.what() << "; earlier report sections preserved\n";
            }
            session.flush();
            lifetime.budget(30000);
        };
        enum class StopReason { TargetExited, CompanionUnavailable, TargetWaitFailed, UnexpectedWaitResult };
        StopReason stopReason = StopReason::TargetExited;
        for (;;) {
            lifetime.budget(30000);
            DWORD targetWait = WaitForSingleObject(target, 200);
            if (targetWait == WAIT_OBJECT_0) {
                DWORD exitCode = 0;
                bool exitCodeKnown = GetExitCodeProcess(target, &exitCode) != FALSE;
                if (exitCodeKnown)
                    session << "process_exit_code=0x" << std::hex << exitCode << std::dec << '\n';
                else
                    session << "process_exit_code_query_error=" << GetLastError() << '\n';
                persistHistory();
                if (fs::read(state->faultCount) || !exitCodeKnown || exitCode != 0) {
                    std::ofstream evidence(folder / ("exit-evidence-" + std::to_string(state->pid) + ".log"));
                    if (!evidence) {
                        session << "exit_evidence_write_failed\n";
                        session.flush();
                    } else {
                        evidence << "Observed process termination, PID=" << state->pid << " runtime=" << state->runtime << '\n';
                        if (exitCodeKnown)
                            evidence << "exit_code=0x" << std::hex << exitCode << std::dec
                                     << " classification=" << (exitCode ? "nonzero_exit_unclassified" : "zero_exit") << '\n';
                        else evidence << "exit_code=unavailable classification=unknown_exit_status\n";
                        evidence << fs::externalCrashEvidence(gameImage, state, processModules);
                        exceptionJournal.write(evidence);
                        evidence << contextEvidence()
                                 << fs::eventHistory(state) << history.text();
                        evidence << "No live process snapshot is available after termination. Correlate with a crash logger dump; a nonzero exit alone does not identify a crash cause.\n";
                        evidence.flush();
                        if (!evidence) {
                            session << "exit_evidence_write_failed_during_write_or_flush\n";
                            session.flush();
                        }
                    }
                }
                stopReason = StopReason::TargetExited;
                break;
            }
            if (targetWait == WAIT_FAILED) {
                session << "target_wait_failed=" << GetLastError() << '\n';
                stopReason = StopReason::TargetWaitFailed;
                break;
            }
            if (targetWait != WAIT_TIMEOUT) {
                session << "target_wait_unexpected_result=" << targetWait << '\n';
                stopReason = StopReason::UnexpectedWaitResult;
                break;
            }
            if (fs::read(state->ready) < 0) {
                stopReason = StopReason::CompanionUnavailable;
                break;
            }
            auto t = fs::now();
            InterlockedExchange64(&state->monitorPulse, t);
            if (t - lastContextPoll >= 500) {
                currentContext = context.sample(); contextTick = t; lastContextPoll = t;
                if (currentContext.cellValid) {
                    lastReadable.cellValid = true; lastReadable.cell = currentContext.cell; lastReadable.cellName = currentContext.cellName;
                    lastReadable.origin = currentContext.origin; lastReadable.files = currentContext.files; lastCellTick = t;
                }
                if (currentContext.menusValid) { lastReadable.menusValid = true; lastReadable.menus = currentContext.menus; lastMenusTick = t; }
                lastReadable.status = "last readable cell/menu fields; timestamps above are independent";
                if (!contextSeen || currentContext != lastContext) {
                    std::ostringstream changes;
                    changes << "CONTEXT_OBSERVATION tick=" << t << '\n' << currentContext.text();
                    if (contextSeen && currentContext.cellValid && lastContext.cellValid && currentContext.cell != lastContext.cell)
                        changes << "cell_changed_from=0x" << std::hex << lastContext.cell << " to=0x" << currentContext.cell << std::dec << '\n';
                    if (contextSeen && currentContext.menusValid && lastContext.menusValid) {
                        for (const auto& name : currentContext.menus)
                            if (std::find(lastContext.menus.begin(), lastContext.menus.end(), name) == lastContext.menus.end())
                                changes << "menu_open_observed=[" << name << "]\n";
                        for (const auto& name : lastContext.menus)
                            if (std::find(currentContext.menus.begin(), currentContext.menus.end(), name) == currentContext.menus.end())
                                changes << "menu_close_observed=[" << name << "]\n";
                    }
                    history.add(changes.str()); session << changes.str(); session.flush();
                    lastContext = currentContext; contextSeen = true; persistHistory();
                }
            }
            if (t - inventoryTime >= 10000) {
                std::array<HMODULE, 2048> modules{}; DWORD needed = 0;
                if (EnumProcessModulesEx(target, modules.data(), sizeof(modules), &needed, LIST_MODULES_64BIT) &&
                    (needed != previousModuleBytes || modules != previousModules)) {
                    session << "LIVE_MODULE_INVENTORY tick=" << t << " (address context for later exit evidence)\n";
                    std::vector<fs::CrashModuleIdentity> inventory;
                    for (size_t i = 0; i < std::min<size_t>(modules.size(), needed / sizeof(HMODULE)); ++i) {
                        MODULEINFO info{}; std::array<wchar_t, 32768> path{};
                        if (GetModuleInformation(target, modules[i], &info, sizeof(info)) &&
                            GetModuleFileNameExW(target, modules[i], path.data(), static_cast<DWORD>(path.size()))) {
                            auto imageName = fs::diagnosticUtf8(std::filesystem::path(path.data()).filename().wstring());
                            session << "base=0x" << std::hex << reinterpret_cast<DWORD64>(info.lpBaseOfDll) << " size=0x"
                                    << info.SizeOfImage << std::dec << ' ' << fs::diagnosticUtf8(path.data()) << '\n';
                            inventory.push_back({reinterpret_cast<DWORD64>(info.lpBaseOfDll), info.SizeOfImage,
                                                 std::move(imageName)});
                        }
                    }
                    session.flush();
                    if (!inventory.empty()) processModules.swap(inventory);
                    previousModules = modules; previousModuleBytes = needed;
                }
                inventoryTime = t;
            }
            LONG64 main = fs::read(state->pulse[0]), ui = fs::read(state->pulse[1]);
            if (!state->taskMonitoring) {
                Window window{state->pid}; EnumWindows(findWindow, reinterpret_cast<LPARAM>(&window));
                DWORD_PTR response = 0;
                if (window.handle && SendMessageTimeoutW(window.handle, WM_NULL, 0, 0,
                        SMTO_ABORTIFHUNG | SMTO_BLOCK, 100, &response)) windowPulse = t;
                main = ui = windowPulse;
            }
            DWORD timeout = fs::read(state->phase) || currentContext.loading() ? state->loadingMs : state->timeoutMs;
            LONG event = fs::read(state->event);
            LONG64 eventTime = fs::read(state->eventTime);
            if (event != lastEvent || eventTime != lastEventTime) {
                session << "tick=" << eventTime << " F4SE event=" << event << " loading/saving=" << fs::read(state->phase) << '\n';
                session.flush(); lastEvent = event; lastEventTime = eventTime;
            }
            // System sleep and a paused debugger can suspend the observer too.
            if (t - lastPoll > 5000) {
                session << "Observer scheduling gap=" << t - lastPoll << "ms; granting one timeout for fresh progress\n";
                session.flush();
                fs::profile(target, false, state, true);
                earlyCount = 0;
                lifetime.budget(timeout + 30000);
                WaitForSingleObject(target, timeout);
                lastPoll = fs::now();
                continue;
            }
            lastPoll = t;
            auto published = fs::read(state->eventCount);
            if (published != lastPublished) {
                session << fs::eventHistory(state, lastPublished); session.flush(); lastPublished = published;
                persistHistory();
            }
            bool paused = fs::read(state->phase) != 0 || currentContext.loading() || !fs::read(state->ready);
            if (paused != profilePaused) {
                fs::profile(target, false, state, true);
                profilePaused = paused;
                earlyCount = 0;
                frameGate.reset();
                session << "tick=" << t << " profiling_paused=" << paused << " CPU baseline reset\n";
                session.flush();
            }
            DWORD foregroundPID = 0;
            GetWindowThreadProcessId(GetForegroundWindow(), &foregroundPID);
            auto frameSelection = frames.current();
            auto frame = frameSelection.sample.tick;
            bool frameAvailable = frameSelection.source && frameSelection.sample.count >= 10;
            bool frameActive = state->frameMonitoring && frameAvailable && !paused && foregroundPID == state->pid;
            bool queuesSlow = main && ui && (t - main >= state->earlyMs || t - ui >= state->earlyMs);
            bool framesSlow = frameActive && t - frame >= state->earlyMs;
            bool early = !paused && state->earlyMs && !gate.reported && earlyCount < 12 &&
                (queuesSlow || framesSlow) && t - lastEarly >= 1000;
            if (early || (!paused && t - lastProfile >= state->profileMs)) {
                std::ostringstream progress;
                progress << "PROGRESS tick=" << t << " normal_count=" << fs::read(state->sequence[0]) << " ui_count=" << fs::read(state->sequence[1])
                    << " present_count=" << fs::read(state->frameCount) << " present_tick=" << frame << " frame_source="
                    << fs::read(state->frameSource) << " ETW_status=" << fs::read(state->frameStatus) << '\n';
                history.add(progress.str() + fs::profile(target, early, state));
                lastProfile = fs::now(); if (early) { lastEarly = lastProfile; ++earlyCount; }
                persistHistory(); lastPoll = fs::now();
            }
            if (!queuesSlow && !framesSlow) earlyCount = 0;
            if (t - lastRetention >= 60000 && !paused) {
                fs::retain(folder, state->maxFreezeReports, state->maxManualReports, state->storageMB, sessionPath); lastRetention = t;
            }
            // A profiling pass can outlive the silence that triggered it.
            t = fs::now();
            if (state->taskMonitoring) { main = fs::read(state->pulse[0]); ui = fs::read(state->pulse[1]); }
            else {
                Window window{state->pid}; EnumWindows(findWindow, reinterpret_cast<LPARAM>(&window));
                DWORD_PTR response = 0;
                if (window.handle && SendMessageTimeoutW(window.handle, WM_NULL, 0, 0, SMTO_ABORTIFHUNG | SMTO_BLOCK, 100, &response)) windowPulse = t;
                main = ui = windowPulse;
            }
            // Re-read context after profiling; a newly opened loading screen must affect this decision.
            if (fs::now() - contextTick >= 500) { currentContext = context.sample(); contextTick = fs::now(); }
            paused = fs::read(state->phase) != 0 || currentContext.loading() || !fs::read(state->ready);
            timeout = fs::read(state->phase) || currentContext.loading() ? state->loadingMs : state->timeoutMs;
            frameSelection = frames.current();
            frame = frameSelection.sample.tick;
            frameAvailable = frameSelection.source && frameSelection.sample.count >= 10;
            GetWindowThreadProcessId(GetForegroundWindow(), &foregroundPID);
            if (fs::read(state->ready) && gate.sample(t, fs::read(state->started), main, ui, timeout, state->startupMs)) {
                std::string reason = !state->taskMonitoring ? "window-not-responding" : !main || !ui ? "startup-task-silence" :
                    (t - main >= timeout && t - ui >= timeout ? "both-task-queues-stalled" :
                    (t - main >= timeout ? "normal-task-queue-stalled" : "ui-task-queue-stalled"));
                // Background-but-responsive stalls are usually Alt-Tab pauses, not freezes.
                Window probe{state->pid};
                EnumWindows(findWindow, reinterpret_cast<LPARAM>(&probe));
                DWORD_PTR probeResponse = 0;
                bool responsive = probe.handle && SendMessageTimeoutW(probe.handle, WM_NULL, 0, 0,
                    SMTO_ABORTIFHUNG | SMTO_BLOCK, 100, &probeResponse);
                auto decision = suppression.evaluate(state->suppressBackground != 0,
                    foregroundPID == state->pid, paused, responsive, t,
                    std::min(main, ui), state->foregroundGraceSec);
                if (decision.suppress) {
                    if (!suppressionLogged) {
                        session << "tick=" << t << " hang_suppressed reason="
                                << fs::suppressionReasonName(decision.reason) << '\n';
                        session.flush();
                        suppressionLogged = true;
                    }
                    gate.rearm();
                    lastPoll = fs::now();
                } else {
                    if (suppressionLogged) {
                        session << "tick=" << t << " hang_suppression_lifted\n";
                        session.flush();
                    }
                    suppression.reset();
                    suppressionLogged = false;
                    collect(reason);
                    lastPoll = fs::now();
                }
            } else if (!gate.reported) {
                suppression.reset();
                suppressionLogged = false;
            }
            if (wasReported && !gate.reported) { session << "tick=" << t << " queues recovered\n"; session.flush(); }
            wasReported = gate.reported;
            bool frameIncident = frameGate.sample(t, state->frameMonitoring ? frameSelection : fs::FrameSelection{},
                                                  foregroundPID == state->pid, paused, timeout);
            if (!gate.reported && frameIncident) {
                collect("present-silence-with-task-progress"); lastPoll = fs::now();
            }
            bool keyDown = state->manualKey && (GetAsyncKeyState(static_cast<int>(state->manualKey)) & 0x8000);
            if (keyDown && !keyWasDown && foregroundPID == state->pid && t - lastManual >= 5000) {
                collect("manual-capture");
                lastPoll = fs::now(); lastManual = t;
            }
            keyWasDown = keyDown;
            if (session.tellp() > 8 * 1024 * 1024) {
                session.close(); session.open(sessionPath, std::ios::trunc);
                session << "Session text rotated at 8 MiB. PID=" << state->pid << fs::eventHistory(state);
                session.flush();
            }
            if (!session) return 6;
        }
        switch (stopReason) {
        case StopReason::TargetExited: session << "Target process exited; monitoring stopped\n"; break;
        case StopReason::CompanionUnavailable: session << "Monitoring stopped because the companion revoked the session\n"; break;
        case StopReason::TargetWaitFailed: session << "Monitoring stopped after target wait failure\n"; break;
        case StopReason::UnexpectedWaitResult: session << "Monitoring stopped after an unexpected target wait result\n"; break;
        }
        session.flush();
    } catch (...) { return 6; }
    return 0;
}
