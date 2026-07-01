#include "NtQueryInformationProcessMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <sstream>
#include <string>
#include <string_view>

namespace {

using NtQueryInformationProcessFn = LONG(NTAPI*)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

constexpr ULONG kProcessBasicInformation = 0;
constexpr ULONG kProcessDebugPort = 7;
constexpr ULONG kProcessDebugObjectHandle = 30;
constexpr ULONG kProcessDebugFlags = 31;
constexpr LONG kStatusPortNotSet = static_cast<LONG>(0xC0000353);

struct ProcessBasicInformation {
    LONG exit_status;
    PVOID peb_base_address;
    ULONG_PTR affinity_mask;
    LONG base_priority;
    ULONG_PTR unique_process_id;
    ULONG_PTR inherited_from_unique_process_id;
};

bool NtSuccess(LONG status) {
    return status >= 0;
}

NtQueryInformationProcessFn ResolveNtQueryInformationProcess() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        ntdll = LoadLibraryW(L"ntdll.dll");
    }

    if (ntdll == nullptr) {
        return nullptr;
    }

    return reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
}

std::wstring Hex64(std::uint64_t value) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

std::wstring Hex32(std::uint32_t value) {
    return Hex64(value);
}

std::wstring StatusHex(LONG status) {
    return Hex32(static_cast<std::uint32_t>(status));
}

std::wstring ToLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

std::wstring ProcessNameFromSnapshot(DWORD pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return L"<snapshot failed>";
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    std::wstring process_name = L"<not found>";
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == pid) {
                process_name = entry.szExeFile;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return process_name;
}

std::wstring_view DebuggerParentMatch(std::wstring_view lower_image_name) {
    static constexpr std::wstring_view kDebuggerParents[] = {
        L"x64dbg.exe",
        L"x32dbg.exe",
        L"ida.exe",
        L"ida64.exe",
        L"ollydbg.exe",
        L"windbg.exe",
        L"cdb.exe",
        L"ntsd.exe",
    };

    for (std::wstring_view debugger_parent : kDebuggerParents) {
        if (lower_image_name == debugger_parent) {
            return debugger_parent;
        }
    }

    return {};
}

std::wstring ParentDetails(const ProcessBasicInformation& info, const std::wstring& parent_name) {
    std::wstringstream stream;
    stream
        << L"UniqueProcessId=" << static_cast<DWORD>(info.unique_process_id)
        << L", InheritedFromUniqueProcessId=" << static_cast<DWORD>(info.inherited_from_unique_process_id)
        << L", parent image=" << parent_name;
    return stream.str();
}

}  // namespace

namespace adt {

std::wstring_view NtQueryProcessDebugPortMechanism::Id() const noexcept {
    return L"nt_query_information_process.debug_port";
}

std::wstring_view NtQueryProcessDebugPortMechanism::Name() const noexcept {
    return L"NtQIP ProcessDebugPort";
}

std::wstring_view NtQueryProcessDebugPortMechanism::Category() const noexcept {
    return L"NtQueryInformationProcess";
}

std::wstring_view NtQueryProcessDebugPortMechanism::Description() const noexcept {
    return L"Queries ProcessDebugPort and treats a nonzero debug port as debugger evidence.";
}

MechanismResult NtQueryProcessDebugPortMechanism::Run(const MechanismContext&) {
    const auto nt_query_information_process = ResolveNtQueryInformationProcess();
    if (nt_query_information_process == nullptr) {
        return MechanismResult::Error(L"NtQueryInformationProcess is unavailable");
    }

    ULONG_PTR debug_port = 0;
    ULONG return_length = 0;
    const LONG status = nt_query_information_process(
        GetCurrentProcess(),
        kProcessDebugPort,
        &debug_port,
        sizeof(debug_port),
        &return_length);

    const std::wstring detail =
        L"Status=" + StatusHex(status) +
        L", ProcessDebugPort=" + Hex64(static_cast<std::uint64_t>(debug_port)) +
        L", ReturnLength=" + std::to_wstring(return_length);

    if (!NtSuccess(status)) {
        return MechanismResult::Error(detail);
    }

    if (debug_port != 0) {
        return MechanismResult::Detected(detail);
    }

    return MechanismResult::Clean(detail);
}

std::wstring_view NtQueryProcessDebugFlagsMechanism::Id() const noexcept {
    return L"nt_query_information_process.debug_flags";
}

std::wstring_view NtQueryProcessDebugFlagsMechanism::Name() const noexcept {
    return L"NtQIP ProcessDebugFlags";
}

std::wstring_view NtQueryProcessDebugFlagsMechanism::Category() const noexcept {
    return L"NtQueryInformationProcess";
}

std::wstring_view NtQueryProcessDebugFlagsMechanism::Description() const noexcept {
    return L"Queries ProcessDebugFlags; zero commonly indicates a debugged process.";
}

MechanismResult NtQueryProcessDebugFlagsMechanism::Run(const MechanismContext&) {
    const auto nt_query_information_process = ResolveNtQueryInformationProcess();
    if (nt_query_information_process == nullptr) {
        return MechanismResult::Error(L"NtQueryInformationProcess is unavailable");
    }

    ULONG debug_flags = 0;
    ULONG return_length = 0;
    const LONG status = nt_query_information_process(
        GetCurrentProcess(),
        kProcessDebugFlags,
        &debug_flags,
        sizeof(debug_flags),
        &return_length);

    const std::wstring detail =
        L"Status=" + StatusHex(status) +
        L", ProcessDebugFlags=" + Hex32(debug_flags) +
        L", ReturnLength=" + std::to_wstring(return_length);

    if (!NtSuccess(status)) {
        return MechanismResult::Error(detail);
    }

    if (debug_flags == 0) {
        return MechanismResult::Detected(detail);
    }

    return MechanismResult::Clean(detail);
}

std::wstring_view NtQueryProcessDebugObjectHandleMechanism::Id() const noexcept {
    return L"nt_query_information_process.debug_object_handle";
}

std::wstring_view NtQueryProcessDebugObjectHandleMechanism::Name() const noexcept {
    return L"NtQIP DebugObjectHandle";
}

std::wstring_view NtQueryProcessDebugObjectHandleMechanism::Category() const noexcept {
    return L"NtQueryInformationProcess";
}

std::wstring_view NtQueryProcessDebugObjectHandleMechanism::Description() const noexcept {
    return L"Queries ProcessDebugObjectHandle; a returned debug object handle indicates debugging.";
}

MechanismResult NtQueryProcessDebugObjectHandleMechanism::Run(const MechanismContext&) {
    const auto nt_query_information_process = ResolveNtQueryInformationProcess();
    if (nt_query_information_process == nullptr) {
        return MechanismResult::Error(L"NtQueryInformationProcess is unavailable");
    }

    HANDLE debug_object = nullptr;
    ULONG return_length = 0;
    const LONG status = nt_query_information_process(
        GetCurrentProcess(),
        kProcessDebugObjectHandle,
        &debug_object,
        sizeof(debug_object),
        &return_length);

    const std::wstring detail =
        L"Status=" + StatusHex(status) +
        L", ProcessDebugObjectHandle=" +
        Hex64(reinterpret_cast<std::uint64_t>(debug_object)) +
        L", ReturnLength=" + std::to_wstring(return_length);

    if (NtSuccess(status)) {
        if (debug_object != nullptr && debug_object != INVALID_HANDLE_VALUE) {
            CloseHandle(debug_object);
            return MechanismResult::Detected(detail);
        }

        return MechanismResult::Clean(detail);
    }

    if (status == kStatusPortNotSet) {
        return MechanismResult::Clean(detail);
    }

    return MechanismResult::Error(detail);
}

std::wstring_view NtQueryProcessBasicInformationMechanism::Id() const noexcept {
    return L"nt_query_information_process.basic_information";
}

std::wstring_view NtQueryProcessBasicInformationMechanism::Name() const noexcept {
    return L"NtQIP parent process";
}

std::wstring_view NtQueryProcessBasicInformationMechanism::Category() const noexcept {
    return L"NtQueryInformationProcess";
}

std::wstring_view NtQueryProcessBasicInformationMechanism::Description() const noexcept {
    return L"Queries ProcessBasicInformation and checks the inherited parent process.";
}

MechanismResult NtQueryProcessBasicInformationMechanism::Run(const MechanismContext&) {
    const auto nt_query_information_process = ResolveNtQueryInformationProcess();
    if (nt_query_information_process == nullptr) {
        return MechanismResult::Error(L"NtQueryInformationProcess is unavailable");
    }

    ProcessBasicInformation info = {};
    ULONG return_length = 0;
    const LONG status = nt_query_information_process(
        GetCurrentProcess(),
        kProcessBasicInformation,
        &info,
        sizeof(info),
        &return_length);

    if (!NtSuccess(status)) {
        return MechanismResult::Error(
            L"Status=" + StatusHex(status) +
            L", ReturnLength=" + std::to_wstring(return_length));
    }

    const DWORD parent_pid = static_cast<DWORD>(info.inherited_from_unique_process_id);
    const std::wstring parent_name = ProcessNameFromSnapshot(parent_pid);
    const std::wstring detail =
        L"Status=" + StatusHex(status) +
        L", ReturnLength=" + std::to_wstring(return_length) +
        L", " + ParentDetails(info, parent_name);

    const std::wstring parent_name_lower = ToLower(parent_name);
    const std::wstring_view debugger_parent = DebuggerParentMatch(parent_name_lower);
    if (!debugger_parent.empty()) {
        return MechanismResult::Detected(
            L"suspicious debugger parent " + std::wstring(debugger_parent) + L"; " + detail);
    }

    return MechanismResult::Clean(detail);
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::NtQueryProcessDebugPortMechanism> g_ntqip_debug_port_registrar;
const ::adt::MechanismRegistrar<::adt::NtQueryProcessDebugFlagsMechanism> g_ntqip_debug_flags_registrar;
const ::adt::MechanismRegistrar<::adt::NtQueryProcessDebugObjectHandleMechanism> g_ntqip_debug_object_handle_registrar;
const ::adt::MechanismRegistrar<::adt::NtQueryProcessBasicInformationMechanism> g_ntqip_basic_information_registrar;
}
