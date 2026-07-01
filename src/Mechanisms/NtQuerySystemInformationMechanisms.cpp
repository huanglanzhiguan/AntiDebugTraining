#include "NtQuerySystemInformationMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using NtQuerySystemInformationFn = LONG(NTAPI*)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

constexpr ULONG kSystemProcessInformation = 5;
constexpr ULONG kSystemKernelDebuggerInformation = 35;
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004);
constexpr LONG kStatusBufferOverflow = static_cast<LONG>(0x80000005);
constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023);
constexpr ULONG kInitialProcessBufferSize = 256 * 1024;
constexpr ULONG kMaximumProcessBufferSize = 16 * 1024 * 1024;

struct NativeUnicodeString {
    USHORT length;
    USHORT maximum_length;
    PWSTR buffer;
};

struct SystemKernelDebuggerInformation {
    BOOLEAN kernel_debugger_enabled;
    BOOLEAN kernel_debugger_not_present;
};

struct SystemProcessInformation {
    ULONG next_entry_offset;
    ULONG number_of_threads;
    LARGE_INTEGER working_set_private_size;
    ULONG hard_fault_count;
    ULONG number_of_threads_high_watermark;
    ULONGLONG cycle_time;
    LARGE_INTEGER create_time;
    LARGE_INTEGER user_time;
    LARGE_INTEGER kernel_time;
    NativeUnicodeString image_name;
    LONG base_priority;
    HANDLE unique_process_id;
    HANDLE inherited_from_unique_process_id;
};

struct ProcessSnapshotEntry {
    DWORD pid = 0;
    DWORD parent_pid = 0;
    std::wstring image_name;
};

struct ProcessSnapshot {
    LONG status = 0;
    ULONG return_length = 0;
    std::vector<ProcessSnapshotEntry> entries;
};

bool NtSuccess(LONG status) {
    return status >= 0;
}

NtQuerySystemInformationFn ResolveNtQuerySystemInformation() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        ntdll = LoadLibraryW(L"ntdll.dll");
    }

    if (ntdll == nullptr) {
        return nullptr;
    }

    return reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
}

std::wstring Hex32(std::uint32_t value) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
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

DWORD HandleToPid(HANDLE handle) {
    return static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(handle));
}

std::wstring ImageNameFromNative(const SystemProcessInformation* info) {
    if (info->image_name.length != 0 && info->image_name.buffer != nullptr) {
        return std::wstring(
            info->image_name.buffer,
            info->image_name.length / sizeof(wchar_t));
    }

    const DWORD pid = HandleToPid(info->unique_process_id);
    if (pid == 0) {
        return L"Idle";
    }

    if (pid == 4) {
        return L"System";
    }

    return L"<unnamed>";
}

bool IsResizeStatus(LONG status) {
    return status == kStatusInfoLengthMismatch ||
        status == kStatusBufferOverflow ||
        status == kStatusBufferTooSmall;
}

ProcessSnapshot QueryProcessSnapshot(NtQuerySystemInformationFn query_system_information) {
    ProcessSnapshot snapshot;
    std::vector<std::uint8_t> buffer(kInitialProcessBufferSize);

    for (;;) {
        snapshot.return_length = 0;
        snapshot.status = query_system_information(
            kSystemProcessInformation,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &snapshot.return_length);

        if (!IsResizeStatus(snapshot.status)) {
            break;
        }

        const ULONG requested_size = snapshot.return_length != 0
            ? snapshot.return_length + (64 * 1024)
            : static_cast<ULONG>(buffer.size() * 2);

        if (requested_size > kMaximumProcessBufferSize ||
            buffer.size() >= kMaximumProcessBufferSize) {
            break;
        }

        buffer.resize(requested_size);
    }

    if (!NtSuccess(snapshot.status)) {
        return snapshot;
    }

    std::uint8_t* cursor = buffer.data();
    for (;;) {
        const auto* info = reinterpret_cast<const SystemProcessInformation*>(cursor);
        snapshot.entries.push_back({
            HandleToPid(info->unique_process_id),
            HandleToPid(info->inherited_from_unique_process_id),
            ImageNameFromNative(info)
        });

        if (info->next_entry_offset == 0) {
            break;
        }

        cursor += info->next_entry_offset;
    }

    return snapshot;
}

const ProcessSnapshotEntry* FindProcessByPid(
    const std::vector<ProcessSnapshotEntry>& entries,
    DWORD pid) {
    const auto found = std::find_if(entries.begin(), entries.end(), [pid](const ProcessSnapshotEntry& entry) {
        return entry.pid == pid;
    });

    return found == entries.end() ? nullptr : &(*found);
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

std::wstring ParentDetails(
    const ProcessSnapshotEntry& current,
    const ProcessSnapshotEntry* parent) {
    std::wstringstream stream;
    stream
        << L"self=" << current.image_name
        << L" pid=" << current.pid
        << L", parent pid=" << current.parent_pid;

    if (parent != nullptr) {
        stream << L", parent image=" << parent->image_name;
    } else {
        stream << L", parent image=<not found>";
    }

    return stream.str();
}

}  // namespace

namespace adt {

std::wstring_view NtQuerySystemKernelDebuggerMechanism::Id() const noexcept {
    return L"nt_query_system_information.kernel_debugger";
}

std::wstring_view NtQuerySystemKernelDebuggerMechanism::Name() const noexcept {
    return L"NtQSI kernel debugger";
}

std::wstring_view NtQuerySystemKernelDebuggerMechanism::Category() const noexcept {
    return L"NtQuerySystemInformation";
}

std::wstring_view NtQuerySystemKernelDebuggerMechanism::Description() const noexcept {
    return L"Queries SystemKernelDebuggerInformation for kernel-debugger state.";
}

MechanismResult NtQuerySystemKernelDebuggerMechanism::Run(const MechanismContext&) {
    const auto query_system_information = ResolveNtQuerySystemInformation();
    if (query_system_information == nullptr) {
        return MechanismResult::Error(L"NtQuerySystemInformation is unavailable");
    }

    SystemKernelDebuggerInformation info{};
    ULONG return_length = 0;
    const LONG status = query_system_information(
        kSystemKernelDebuggerInformation,
        &info,
        sizeof(info),
        &return_length);

    const std::wstring detail =
        L"Status=" + StatusHex(status) +
        L", KernelDebuggerEnabled=" + std::to_wstring(info.kernel_debugger_enabled != FALSE) +
        L", KernelDebuggerNotPresent=" + std::to_wstring(info.kernel_debugger_not_present != FALSE) +
        L", ReturnLength=" + std::to_wstring(return_length);

    if (!NtSuccess(status)) {
        return MechanismResult::Error(detail);
    }

    if (info.kernel_debugger_enabled || !info.kernel_debugger_not_present) {
        return MechanismResult::Detected(detail);
    }

    return MechanismResult::Clean(detail);
}

std::wstring_view NtQuerySystemParentProcessMechanism::Id() const noexcept {
    return L"nt_query_system_information.parent_process";
}

std::wstring_view NtQuerySystemParentProcessMechanism::Name() const noexcept {
    return L"NtQSI parent process";
}

std::wstring_view NtQuerySystemParentProcessMechanism::Category() const noexcept {
    return L"NtQuerySystemInformation";
}

std::wstring_view NtQuerySystemParentProcessMechanism::Description() const noexcept {
    return L"Uses SystemProcessInformation to compare the parent process name with a debugger-parent list.";
}

MechanismResult NtQuerySystemParentProcessMechanism::Run(const MechanismContext&) {
    const auto query_system_information = ResolveNtQuerySystemInformation();
    if (query_system_information == nullptr) {
        return MechanismResult::Error(L"NtQuerySystemInformation is unavailable");
    }

    ProcessSnapshot snapshot = QueryProcessSnapshot(query_system_information);
    if (!NtSuccess(snapshot.status)) {
        return MechanismResult::Error(
            L"Status=" + StatusHex(snapshot.status) +
            L", ReturnLength=" + std::to_wstring(snapshot.return_length));
    }

    const DWORD current_pid = GetCurrentProcessId();
    const ProcessSnapshotEntry* current = FindProcessByPid(snapshot.entries, current_pid);
    if (current == nullptr) {
        return MechanismResult::Error(L"current process was not found in SystemProcessInformation");
    }

    const ProcessSnapshotEntry* parent = FindProcessByPid(snapshot.entries, current->parent_pid);
    const std::wstring detail = ParentDetails(*current, parent);

    if (parent == nullptr) {
        return MechanismResult::Clean(detail);
    }

    const std::wstring parent_image_lower = ToLower(parent->image_name);
    const std::wstring_view debugger_parent = DebuggerParentMatch(parent_image_lower);
    if (!debugger_parent.empty()) {
        return MechanismResult::Detected(
            L"suspicious debugger parent " + std::wstring(debugger_parent) + L"; " + detail);
    }

    return MechanismResult::Clean(detail);
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::NtQuerySystemKernelDebuggerMechanism> g_ntqsi_kernel_debugger_registrar;
const ::adt::MechanismRegistrar<::adt::NtQuerySystemParentProcessMechanism> g_ntqsi_parent_process_registrar;
}
