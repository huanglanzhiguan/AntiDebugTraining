#include "NtUserQueryWindowMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <cwctype>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct ProcessSnapshotEntry {
    DWORD pid = 0;
    std::wstring image_name;
};

struct WindowOwnerMatch {
    HWND hwnd = nullptr;
    DWORD process_id = 0;
    DWORD thread_id = 0;
    std::wstring process_name;
    std::wstring title;
    std::wstring class_name;
    std::wstring_view matched_name;
    unsigned int visited_windows = 0;
};

struct EnumerationState {
    HWND owner_window = nullptr;
    std::vector<ProcessSnapshotEntry> processes;
    WindowOwnerMatch match;
    unsigned int visited_windows = 0;
    unsigned int queryable_windows = 0;
};

std::wstring ToLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

std::wstring HwndHex(HWND hwnd) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase
           << reinterpret_cast<std::uintptr_t>(hwnd);
    return stream.str();
}

std::vector<ProcessSnapshotEntry> CaptureProcessSnapshot() {
    std::vector<ProcessSnapshotEntry> processes;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            processes.push_back({ entry.th32ProcessID, entry.szExeFile });
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return processes;
}

std::wstring ProcessNameFromSnapshot(
    const std::vector<ProcessSnapshotEntry>& processes,
    DWORD pid) {
    const auto found = std::find_if(
        processes.begin(),
        processes.end(),
        [pid](const ProcessSnapshotEntry& process) {
            return process.pid == pid;
        });

    if (found == processes.end()) {
        return L"<not found>";
    }

    return found->image_name;
}

std::wstring WindowTitle(HWND hwnd) {
    const int length = GetWindowTextLengthW(hwnd);
    if (length <= 0) {
        return L"";
    }

    std::wstring title(static_cast<std::size_t>(length + 1), L'\0');
    const int copied = GetWindowTextW(hwnd, title.data(), length + 1);
    title.resize(static_cast<std::size_t>((std::max)(copied, 0)));
    return title;
}

std::wstring WindowClassName(HWND hwnd) {
    wchar_t class_name[256] = {};
    const int copied = GetClassNameW(hwnd, class_name, static_cast<int>(std::size(class_name)));
    if (copied <= 0) {
        return L"";
    }

    return std::wstring(class_name, static_cast<std::size_t>(copied));
}

std::wstring_view DebuggerProcessMatch(std::wstring_view lower_image_name) {
    static constexpr std::wstring_view kDebuggerProcesses[] = {
        L"x64dbg.exe",
        L"x32dbg.exe",
        L"ollydbg.exe",
        L"immunitydebugger.exe",
        L"windbg.exe",
        L"windbgx.exe",
        L"cdb.exe",
        L"ntsd.exe",
        L"ida.exe",
        L"ida64.exe",
        L"idag.exe",
        L"idag64.exe",
        L"idaw.exe",
        L"idaw64.exe",
        L"idaq.exe",
        L"idaq64.exe",
    };

    for (std::wstring_view debugger_process : kDebuggerProcesses) {
        if (lower_image_name == debugger_process) {
            return debugger_process;
        }
    }

    return {};
}

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM parameter) {
    auto* state = reinterpret_cast<EnumerationState*>(parameter);
    ++state->visited_windows;

    if (hwnd == state->owner_window) {
        return TRUE;
    }

    DWORD process_id = 0;
    const DWORD thread_id = GetWindowThreadProcessId(hwnd, &process_id);
    if (thread_id == 0 || process_id == 0) {
        return TRUE;
    }

    ++state->queryable_windows;

    const std::wstring process_name = ProcessNameFromSnapshot(state->processes, process_id);
    const std::wstring process_name_lower = ToLower(process_name);
    const std::wstring_view matched_name = DebuggerProcessMatch(process_name_lower);
    if (matched_name.empty()) {
        return TRUE;
    }

    state->match = {
        hwnd,
        process_id,
        thread_id,
        process_name,
        WindowTitle(hwnd),
        WindowClassName(hwnd),
        matched_name,
        state->visited_windows
    };
    return FALSE;
}

std::wstring ErrorDetail(DWORD error) {
    std::wstringstream stream;
    stream << L"EnumWindows failed, GetLastError=" << error;
    return stream.str();
}

std::wstring MatchDetail(const WindowOwnerMatch& match) {
    std::wstringstream stream;
    stream
        << L"GetWindowThreadProcessId matched owner process "
        << match.matched_name
        << L", HWND="
        << HwndHex(match.hwnd)
        << L", PID="
        << match.process_id
        << L", TID="
        << match.thread_id
        << L", image="
        << match.process_name
        << L", title=\""
        << match.title
        << L"\", class=\""
        << match.class_name
        << L"\", visited="
        << match.visited_windows;
    return stream.str();
}

}  // namespace

namespace adt {

std::wstring_view NtUserQueryWindowOwnerProcessMechanism::Id() const noexcept {
    return L"nt_user_query_window.owner_process";
}

std::wstring_view NtUserQueryWindowOwnerProcessMechanism::Name() const noexcept {
    return L"NtUserQueryWindow owner";
}

std::wstring_view NtUserQueryWindowOwnerProcessMechanism::Category() const noexcept {
    return L"NtUserQueryWindow";
}

std::wstring_view NtUserQueryWindowOwnerProcessMechanism::Description() const noexcept {
    return L"Uses GetWindowThreadProcessId to map windows to owner processes and checks debugger image names.";
}

MechanismResult NtUserQueryWindowOwnerProcessMechanism::Run(const MechanismContext& context) {
    EnumerationState state;
    state.owner_window = context.owner_window;
    state.processes = CaptureProcessSnapshot();

    if (state.processes.empty()) {
        return MechanismResult::Error(L"CreateToolhelp32Snapshot could not enumerate processes");
    }

    SetLastError(ERROR_SUCCESS);
    const BOOL completed = EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&state));
    const DWORD last_error = GetLastError();

    if (state.match.hwnd != nullptr) {
        return MechanismResult::Detected(MatchDetail(state.match));
    }

    if (!completed && last_error != ERROR_SUCCESS) {
        return MechanismResult::Error(ErrorDetail(last_error));
    }

    return MechanismResult::Clean(
        L"EnumWindows visited " + std::to_wstring(state.visited_windows) +
        L" top-level windows; " + std::to_wstring(state.queryable_windows) +
        L" had owner PIDs; no configured debugger owner process matched");
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::NtUserQueryWindowOwnerProcessMechanism>
    g_nt_user_query_window_owner_process_registrar;
}
