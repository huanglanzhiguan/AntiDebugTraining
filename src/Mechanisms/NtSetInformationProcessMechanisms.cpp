#include "NtSetInformationProcessMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <sstream>
#include <string>

namespace {

using NtQueryInformationProcessFn = LONG(NTAPI*)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

using NtSetInformationProcessFn = LONG(NTAPI*)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength);

constexpr ULONG kProcessHandleTracing = 32;
constexpr LONG kStatusInvalidParameter = static_cast<LONG>(0xC000000D);
constexpr LONG kStatusInvalidInfoClass = static_cast<LONG>(0xC0000003);
constexpr LONG kStatusNotImplemented = static_cast<LONG>(0xC0000002);

struct ClientId {
    HANDLE unique_process;
    HANDLE unique_thread;
};

struct ProcessHandleTracingEntry {
    HANDLE handle;
    ClientId client_id;
    ULONG type;
    void* stacks[16];
};

struct ProcessHandleTracingQuery {
    HANDLE handle;
    ULONG total_traces;
    ProcessHandleTracingEntry handle_trace[1];
};

struct ProcessHandleTracingProbe {
    LONG status = 0;
    ULONG return_length = 0;
    ULONG total_traces = 0;
};

bool NtSuccess(LONG status) {
    return status >= 0;
}

FARPROC ResolveNativeRoutine(const char* name) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        ntdll = LoadLibraryW(L"ntdll.dll");
    }

    if (ntdll == nullptr) {
        return nullptr;
    }

    return GetProcAddress(ntdll, name);
}

NtQueryInformationProcessFn ResolveNtQueryInformationProcess() {
    return reinterpret_cast<NtQueryInformationProcessFn>(
        ResolveNativeRoutine("NtQueryInformationProcess"));
}

NtSetInformationProcessFn ResolveNtSetInformationProcess() {
    return reinterpret_cast<NtSetInformationProcessFn>(
        ResolveNativeRoutine("NtSetInformationProcess"));
}

std::wstring Hex32(std::uint32_t value) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

std::wstring StatusHex(LONG status) {
    return Hex32(static_cast<std::uint32_t>(status));
}

ProcessHandleTracingProbe QueryProcessHandleTracing(NtQueryInformationProcessFn query_function) {
    std::array<std::uint8_t, 16 * 1024> buffer{};
    auto* query = reinterpret_cast<ProcessHandleTracingQuery*>(buffer.data());
    query->handle = nullptr;

    ProcessHandleTracingProbe probe;
    probe.status = query_function(
        GetCurrentProcess(),
        kProcessHandleTracing,
        query,
        static_cast<ULONG>(buffer.size()),
        &probe.return_length);
    probe.total_traces = query->total_traces;
    return probe;
}

bool IsUnsupportedStatus(LONG status) {
    return status == kStatusInvalidInfoClass ||
        status == kStatusNotImplemented;
}

std::wstring ProbeDetails(
    const ProcessHandleTracingProbe& before,
    LONG enable_status,
    const ProcessHandleTracingProbe& after_enable,
    LONG disable_status) {
    std::wstringstream stream;
    stream
        << L"before Status=" << StatusHex(before.status)
        << L", traces=" << before.total_traces
        << L", len=" << before.return_length
        << L"; enable Status=" << StatusHex(enable_status)
        << L"; after Status=" << StatusHex(after_enable.status)
        << L", traces=" << after_enable.total_traces
        << L", len=" << after_enable.return_length
        << L"; disable Status=" << StatusHex(disable_status);
    return stream.str();
}

}  // namespace

namespace adt {

std::wstring_view NtSetProcessHandleTracingMechanism::Id() const noexcept {
    return L"nt_set_information_process.handle_tracing";
}

std::wstring_view NtSetProcessHandleTracingMechanism::Name() const noexcept {
    return L"NtSIP ProcessHandleTracing";
}

std::wstring_view NtSetProcessHandleTracingMechanism::Category() const noexcept {
    return L"NtSetInformationProcess";
}

std::wstring_view NtSetProcessHandleTracingMechanism::Description() const noexcept {
    return L"Queries, enables, then disables ProcessHandleTracing on the current process.";
}

bool NtSetProcessHandleTracingMechanism::SupportsLiveMode() const noexcept {
    return false;
}

MechanismResult NtSetProcessHandleTracingMechanism::Run(const MechanismContext&) {
    const auto query_information_process = ResolveNtQueryInformationProcess();
    const auto set_information_process = ResolveNtSetInformationProcess();

    if (query_information_process == nullptr || set_information_process == nullptr) {
        return MechanismResult::Error(L"NtQueryInformationProcess or NtSetInformationProcess is unavailable");
    }

    const ProcessHandleTracingProbe before = QueryProcessHandleTracing(query_information_process);

    ULONG enable_flags = 0;
    const LONG enable_status = set_information_process(
        GetCurrentProcess(),
        kProcessHandleTracing,
        &enable_flags,
        sizeof(enable_flags));

    const ProcessHandleTracingProbe after_enable = QueryProcessHandleTracing(query_information_process);

    const LONG disable_status = set_information_process(
        GetCurrentProcess(),
        kProcessHandleTracing,
        nullptr,
        0);

    const std::wstring detail = ProbeDetails(
        before,
        enable_status,
        after_enable,
        disable_status);

    if (IsUnsupportedStatus(before.status) || IsUnsupportedStatus(enable_status)) {
        return MechanismResult::NotApplicable(L"ProcessHandleTracing is not supported here; " + detail);
    }

    if (NtSuccess(before.status)) {
        return MechanismResult::Detected(L"ProcessHandleTracing was already enabled; " + detail);
    }

    if (before.status != kStatusInvalidParameter) {
        return MechanismResult::Clean(L"ProcessHandleTracing was not already enabled; " + detail);
    }

    return MechanismResult::Clean(L"ProcessHandleTracing was disabled before trigger; " + detail);
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::NtSetProcessHandleTracingMechanism> g_ntsip_handle_tracing_registrar;
}
