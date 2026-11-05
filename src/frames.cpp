#include "frames.hpp"
#include <tdh.h>

namespace fs {
namespace {
constexpr GUID dxgi{0xca11c036,0x0102,0x4a2d,{0xa6,0xad,0xf0,0x3c,0xfe,0xd5,0xd3,0xc9}};
bool property(const EVENT_RECORD& event, const wchar_t* name, DWORD& value) {
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name); descriptor.ArrayIndex = ULONG_MAX;
    return TdhGetProperty(const_cast<EVENT_RECORD*>(&event), 0, nullptr, 1, &descriptor, sizeof(value),
                          reinterpret_cast<BYTE*>(&value)) == ERROR_SUCCESS;
}
}
void WINAPI FrameObserver::receive(EVENT_RECORD* event) {
    try { if (event && event->UserContext) static_cast<FrameObserver*>(event->UserContext)->accept(*event); }
    catch (...) { if (event && event->UserContext) InterlockedExchange(&static_cast<FrameObserver*>(event->UserContext)->state->frameStatus, ERROR_OUTOFMEMORY); }
}
ULONG WINAPI FrameObserver::buffers(EVENT_TRACE_LOGFILEW* log) {
    if (log && log->EventsLost && log->Context)
        InterlockedExchange(&static_cast<FrameObserver*>(log->Context)->state->frameStatus, ERROR_INVALID_DATA);
    return TRUE;
}
void FrameObserver::accept(const EVENT_RECORD& event) {
    if (event.EventHeader.ProcessId != state->pid || !IsEqualGUID(event.EventHeader.ProviderId, dxgi) ||
        event.EventHeader.EventDescriptor.Version != 0 || read(state->frameSource) == 2) return;
    DWORD id = event.EventHeader.EventDescriptor.Id;
    if (id == 42) {
        DWORD flags = 0;
        if (property(event, L"Flags", flags)) {
            if (pending.size() > 4096) pending.clear();
            pending[event.EventHeader.ThreadId] = flags;
        }
        return;
    }
    if (id != 43) return;
    auto found = pending.find(event.EventHeader.ThreadId);
    if (found == pending.end()) return;
    DWORD flags = found->second; pending.erase(found);
    DWORD result = 0;
    if ((flags & 1) || !property(event, L"Result", result) || result != S_OK) return;
    InterlockedExchange(&state->frameSource, 1);
    InterlockedExchange(&state->frameThread, event.EventHeader.ThreadId);
    InterlockedExchange64(&state->frameTick, now());
    InterlockedIncrement64(&state->frameCount);
}
ULONG FrameObserver::start() {
    InterlockedExchange(&state->frameStatus, ERROR_IO_PENDING);
    if (!state->frameMonitoring) return ERROR_NOT_SUPPORTED;
    name = L"FreezeSentryF4-" + std::to_wstring(state->pid) + L"-" + std::to_wstring(read(state->processCreated));
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
    properties->Wnode.BufferSize = static_cast<ULONG>(buffer.size());
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID; properties->Wnode.ClientContext = 1;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    properties->BufferSize = 64; properties->MinimumBuffers = 2; properties->MaximumBuffers = 8;
    properties->FlushTimer = 1;
    ULONG error = StartTraceW(&session, name.c_str(), properties);
    if (error) { session = 0; return error; }
    ENABLE_TRACE_PARAMETERS params{}; params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    EVENT_FILTER_DESCRIPTOR filter{}; DWORD pid = state->pid;
    filter.Ptr = reinterpret_cast<ULONGLONG>(&pid); filter.Size = sizeof(pid); filter.Type = EVENT_FILTER_TYPE_PID;
    params.EnableFilterDesc = &filter; params.FilterDescCount = 1;
    error = EnableTraceEx2(session, &dxgi, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
                           0x8000000000000002ULL, 0, 0, &params);
    if (error) return error;
    EVENT_TRACE_LOGFILEW trace{};
    trace.LoggerName = name.data(); trace.Context = this;
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = receive;
    trace.BufferCallback = buffers;
    consumer = OpenTraceW(&trace);
    if (consumer == INVALID_PROCESSTRACE_HANDLE) return GetLastError();
    InterlockedExchange(&state->frameStatus, ERROR_SUCCESS);
    worker = std::thread([this] {
        auto error = ProcessTrace(&consumer, 1, nullptr, nullptr);
        // A clean externally stopped session is no longer a progress source.
        InterlockedExchange(&state->frameStatus, static_cast<LONG>(error ? error : ERROR_BROKEN_PIPE));
    });
    return ERROR_SUCCESS;
}
FrameObserver::~FrameObserver() {
    if (session) ControlTraceW(session, name.c_str(), reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data()), EVENT_TRACE_CONTROL_STOP);
    if (consumer != INVALID_PROCESSTRACE_HANDLE) CloseTrace(consumer);
    if (worker.joinable()) worker.join();
}
}
