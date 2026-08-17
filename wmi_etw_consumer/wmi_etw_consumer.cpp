#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

// Build with MSVC (Developer Command Prompt):
//   cl /std:c++17 /EHsc /MT wmi_etw_consumer.cpp /link advapi32.lib tdh.lib
//
// Run as Administrator:
//   wmi_etw_consumer.exe
//   wmi_etw_consumer.exe my_wmi_etw.log
//
// Stop with Ctrl+C.

static const wchar_t* kSessionName = L"Ajiant-WMI-Activity-Realtime";

// Microsoft-Windows-WMI-Activity
// {1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}
static const GUID kWmiActivityProvider =
{ 0x1418ef04, 0xb0b4, 0x4623, { 0xbf, 0x7e, 0xd7, 0x4a, 0xb4, 0x7b, 0xbd, 0xaa } };

static TRACEHANDLE gSession = 0;
static TRACEHANDLE gTrace = 0;
static PEVENT_TRACE_PROPERTIES gProperties = nullptr;
static std::atomic<bool> gStopping(false);
static FILE* gLogFile = nullptr;
static std::map<USHORT, unsigned long long> gEventCounts;

static void EmitLine(const std::wstring& line)
{
    std::wcout << line << std::endl;
    if (gLogFile) {
        fwprintf(gLogFile, L"%ls\n", line.c_str());
        fflush(gLogFile);
    }
}

static std::wstring WinErrorMessage(ULONG code)
{
    wchar_t* buf = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS;

    DWORD n = FormatMessageW(flags, nullptr, code, 0,
        reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    if (!n || !buf) {
        std::wstringstream ss;
        ss << L"error=" << code;
        return ss.str();
    }

    std::wstring result(buf, n);
    LocalFree(buf);
    while (!result.empty() &&
        (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ')) {
        result.pop_back();
    }
    return result;
}

static std::wstring TimestampToIso8601(const LARGE_INTEGER& timestamp)
{
    FILETIME ft;
    ft.dwLowDateTime = timestamp.LowPart;
    ft.dwHighDateTime = static_cast<DWORD>(timestamp.HighPart);

    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&ft, &st)) {
        return L"<timestamp-conversion-failed>";
    }

    wchar_t out[64]{};
    swprintf_s(out, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return out;
}

static bool GetRawProperty(PEVENT_RECORD eventRecord,
    const wchar_t* propertyName,
    std::vector<BYTE>& value)
{
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
    descriptor.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    ULONG status = TdhGetPropertySize(eventRecord,
        0, nullptr,
        1, &descriptor,
        &size);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    value.assign(size ? size : 1, 0);
    status = TdhGetProperty(eventRecord,
        0, nullptr,
        1, &descriptor,
        size,
        value.data());
    return status == ERROR_SUCCESS;
}

static bool GetStringProperty(PEVENT_RECORD eventRecord,
    const wchar_t* propertyName,
    std::wstring& out)
{
    std::vector<BYTE> raw;
    if (!GetRawProperty(eventRecord, propertyName, raw)) {
        return false;
    }

    if (raw.size() < sizeof(wchar_t)) {
        out.clear();
        return true;
    }

    const wchar_t* p = reinterpret_cast<const wchar_t*>(raw.data());
    const size_t maxChars = raw.size() / sizeof(wchar_t);
    size_t len = 0;
    while (len < maxChars && p[len] != L'\0') {
        ++len;
    }
    out.assign(p, len);
    return true;
}

static bool GetUInt32Property(PEVENT_RECORD eventRecord,
    const wchar_t* propertyName,
    ULONG& out)
{
    std::vector<BYTE> raw;
    if (!GetRawProperty(eventRecord, propertyName, raw) || raw.size() < sizeof(ULONG)) {
        return false;
    }

    memcpy(&out, raw.data(), sizeof(ULONG));
    return true;
}

static std::wstring Present(bool ok, const std::wstring& value)
{
    return ok ? value : L"<not-present>";
}

static std::wstring PresentUInt32(bool ok, ULONG value)
{
    if (!ok) {
        return L"<not-present>";
    }
    std::wstringstream ss;
    ss << value;
    return ss.str();
}

static std::wstring BoolStatus(bool ok)
{
    return ok ? L"OK" : L"MISSING";
}

static void PrintTargetEvent(PEVENT_RECORD eventRecord)
{
    const USHORT id = eventRecord->EventHeader.EventDescriptor.Id;

    std::wstring operation;
    std::wstring ns;
    std::wstring user;
    std::wstring clientMachine;
    std::wstring possibleCause;
    ULONG clientPid = 0;
    ULONG resultCode = 0;

    const bool hasOperation = GetStringProperty(eventRecord, L"Operation", operation);

    bool hasNamespace = GetStringProperty(eventRecord, L"NamespaceName", ns);
    if (!hasNamespace) {
        // Some WMI-Activity event templates use "Namespace" instead.
        hasNamespace = GetStringProperty(eventRecord, L"Namespace", ns);
    }

    const bool hasUser = GetStringProperty(eventRecord, L"User", user);
    const bool hasClientMachine = GetStringProperty(eventRecord, L"ClientMachine", clientMachine);
    const bool hasClientPid = GetUInt32Property(eventRecord, L"ClientProcessId", clientPid);
    const bool hasResultCode = GetUInt32Property(eventRecord, L"ResultCode", resultCode);
    const bool hasPossibleCause = GetStringProperty(eventRecord, L"PossibleCause", possibleCause);

    const std::wstring timestamp = TimestampToIso8601(eventRecord->EventHeader.TimeStamp);
    const ULONG providerPid = eventRecord->EventHeader.ProcessId;

    EmitLine(L"--------------------------------------------------------------------------------");

    {
        std::wstringstream ss;
        ss << L"[TARGET] EventId=" << id
            << L" Version=" << static_cast<unsigned>(eventRecord->EventHeader.EventDescriptor.Version)
            << L" Level=" << static_cast<unsigned>(eventRecord->EventHeader.EventDescriptor.Level);
        EmitLine(ss.str());
    }

    EmitLine(L"TimeStamp       = " + timestamp + L"  [EVENT_HEADER.TimeStamp]");

    {
        std::wstringstream ss;
        ss << L"ProcessId       = " << providerPid << L"  [EVENT_HEADER.ProcessId]";
        EmitLine(ss.str());
    }

    EmitLine(L"ClientProcessId = " + PresentUInt32(hasClientPid, clientPid));
    EmitLine(L"Operation       = " + Present(hasOperation, operation));
    EmitLine(L"Namespace       = " + Present(hasNamespace, ns));
    EmitLine(L"User            = " + Present(hasUser, user));
    EmitLine(L"ClientMachine   = " + Present(hasClientMachine, clientMachine));

    if (id == 5858) {
        if (hasResultCode) {
            std::wstringstream ss;
            ss << L"ResultCode      = 0x"
                << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0')
                << resultCode;
            EmitLine(ss.str());
        }
        else {
            EmitLine(L"ResultCode      = <not-present>");
        }
        EmitLine(L"PossibleCause   = " + Present(hasPossibleCause, possibleCause));
    }

    // These two fields come from EVENT_HEADER and are always structurally available.
    // The remaining fields are checked against the event payload schema at runtime.
    EmitLine(L"FieldCheck      = TimeStamp=OK, ProcessId=OK, ClientProcessId=" + BoolStatus(hasClientPid) +
        L", Operation=" + BoolStatus(hasOperation) +
        L", Namespace=" + BoolStatus(hasNamespace) +
        L", User=" + BoolStatus(hasUser) +
        L", ClientMachine=" + BoolStatus(hasClientMachine));

    if (id == 5858 && !hasNamespace) {
        EmitLine(L"Note            = Event 5858 normally has no dedicated Namespace/NamespaceName payload field; do not infer it from Operation when validating schema coverage.");
    }
}

static VOID WINAPI EventRecordCallback(PEVENT_RECORD eventRecord)
{
    if (!IsEqualGUID(eventRecord->EventHeader.ProviderId, kWmiActivityProvider)) {
        return;
    }

    const USHORT id = eventRecord->EventHeader.EventDescriptor.Id;
    ++gEventCounts[id];

    // Always show which WMI-Activity event IDs are appearing, but keep non-target
    // events compact so the console remains usable.
    {
        std::wstringstream ss;
        ss << L"[WMI] "
            << TimestampToIso8601(eventRecord->EventHeader.TimeStamp)
            << L" EventId=" << id
            << L" HeaderPID=" << eventRecord->EventHeader.ProcessId;
        EmitLine(ss.str());
    }

    if (id == 1 || id == 11 || id == 5858) {
        PrintTargetEvent(eventRecord);
    }
}

static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType)
{
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
        if (!gStopping.exchange(true)) {
            // Stopping the real-time session causes ProcessTrace() to return.
            if (gSession != 0 && gProperties != nullptr) {
                ControlTraceW(gSession, kSessionName, gProperties, EVENT_TRACE_CONTROL_STOP);
            }
        }
        return TRUE;
    }
    return FALSE;
}

static std::vector<BYTE> MakePropertiesBuffer()
{
    const size_t nameBytes = (wcslen(kSessionName) + 1) * sizeof(wchar_t);
    std::vector<BYTE> buffer(sizeof(EVENT_TRACE_PROPERTIES) + nameBytes, 0);

    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
    props->Wnode.BufferSize = static_cast<ULONG>(buffer.size());
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1; // QPC clock; ProcessTrace converts timestamps for us.
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    wchar_t* name = reinterpret_cast<wchar_t*>(buffer.data() + props->LoggerNameOffset);
    memcpy(name, kSessionName, nameBytes);
    return buffer;
}

static void PrintSummary()
{
    EmitLine(L"");
    EmitLine(L"==================== Event summary ====================");

    if (gEventCounts.empty()) {
        EmitLine(L"No Microsoft-Windows-WMI-Activity events were received.");
    }
    else {
        for (const auto& kv : gEventCounts) {
            std::wstringstream ss;
            ss << L"EventId=" << kv.first << L" Count=" << kv.second;
            if (kv.first == 1 || kv.first == 11 || kv.first == 5858) {
                ss << L"  <target>";
            }
            EmitLine(ss.str());
        }
    }

    EmitLine(L"Expected compatibility check:");
    EmitLine(L"  Event 1    : present in the supplied Windows 7 manifest and later manifests.");
    EmitLine(L"  Event 11   : not present in the supplied Windows 7 manifest; present in later Windows manifests.");
    EmitLine(L"  Event 5858 : not present in the supplied Windows 7 manifest; present in later Windows manifests.");
}

int wmain(int argc, wchar_t** argv)
{
    const wchar_t* logPath = (argc >= 2) ? argv[1] : L"wmi_etw.log";
    _wfopen_s(&gLogFile, logPath, L"a+, ccs=UTF-8");

    EmitLine(L"Microsoft-Windows-WMI-Activity real-time ETW consumer");
    EmitLine(L"Provider GUID: {1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}");
    EmitLine(std::wstring(L"Log file: ") + (gLogFile ? logPath : L"<open failed; console only>"));
    EmitLine(L"Targets: Event ID 1, 11, 5858");
    EmitLine(L"Run this program as Administrator, then run wmi_query_tests.bat in another console.");
    EmitLine(L"Press Ctrl+C to stop and print the event summary.");
    EmitLine(L"");

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    // Clean up a stale session from a previous abnormal termination. Use a
    // separate buffer because ControlTrace may write session information into it.
    auto stalePropertiesBuffer = MakePropertiesBuffer();
    auto* staleProperties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stalePropertiesBuffer.data());
    ControlTraceW(0, kSessionName, staleProperties, EVENT_TRACE_CONTROL_STOP);

    auto propertiesBuffer = MakePropertiesBuffer();
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertiesBuffer.data());
    gProperties = properties;

    ULONG status = StartTraceW(&gSession, kSessionName, properties);
    if (status != ERROR_SUCCESS) {
        EmitLine(L"StartTraceW failed: " + std::to_wstring(status) + L" (" + WinErrorMessage(status) + L")");
        if (gLogFile) fclose(gLogFile);
        return 1;
    }

    status = EnableTraceEx2(gSession,
        &kWmiActivityProvider,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFFULL, // all keywords / channel keyword bits
        0,
        0,
        nullptr);
    if (status != ERROR_SUCCESS) {
        EmitLine(L"EnableTraceEx2 failed: " + std::to_wstring(status) + L" (" + WinErrorMessage(status) + L")");
        ControlTraceW(gSession, kSessionName, properties, EVENT_TRACE_CONTROL_STOP);
        if (gLogFile) fclose(gLogFile);
        return 1;
    }

    EVENT_TRACE_LOGFILEW logFile{};
    logFile.LoggerName = const_cast<LPWSTR>(kSessionName);
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;

    gTrace = OpenTraceW(&logFile);
    if (gTrace == INVALID_PROCESSTRACE_HANDLE) {
        const ULONG err = GetLastError();
        EmitLine(L"OpenTraceW failed: " + std::to_wstring(err) + L" (" + WinErrorMessage(err) + L")");
        ControlTraceW(gSession, kSessionName, properties, EVENT_TRACE_CONTROL_STOP);
        if (gLogFile) fclose(gLogFile);
        return 1;
    }

    TRACEHANDLE handles[1] = { gTrace };
    status = ProcessTrace(handles, 1, nullptr, nullptr);

    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED && !gStopping.load()) {
        EmitLine(L"ProcessTrace returned: " + std::to_wstring(status) + L" (" + WinErrorMessage(status) + L")");
    }

    if (gTrace != 0 && gTrace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(gTrace);
        gTrace = 0;
    }

    if (gSession != 0) {
        ControlTraceW(gSession, kSessionName, properties, EVENT_TRACE_CONTROL_STOP);
        gSession = 0;
    }
    gProperties = nullptr;

    PrintSummary();

    if (gLogFile) {
        fclose(gLogFile);
        gLogFile = nullptr;
    }
    return 0;
}