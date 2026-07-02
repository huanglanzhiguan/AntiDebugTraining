#include "NtUserBuildHwndListMechanisms.h"

#include "WindowProbeList.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>

#include <algorithm>
#include <cwctype>
#include <sstream>
#include <string>
#include <string_view>

namespace {

using adt::detail::HwndHex;
using adt::detail::WindowProbe;
using adt::detail::WindowProbeKind;
using adt::detail::WindowProbeKindName;
using adt::detail::kDebuggerWindowProbes;

struct WindowMatch {
    HWND hwnd = nullptr;
    WindowProbe probe {};
    std::wstring title;
    std::wstring class_name;
    unsigned int visited_windows = 0;
};

struct EnumerationState {
    HWND owner_window = nullptr;
    WindowMatch match;
    unsigned int visited_windows = 0;
};

bool SameCharIgnoreCase(wchar_t left, wchar_t right) {
    return std::towlower(left) == std::towlower(right);
}

bool ContainsIgnoreCase(std::wstring_view haystack, std::wstring_view needle) {
    if (haystack.empty() || needle.empty() || needle.size() > haystack.size()) {
        return false;
    }

    return std::search(
        haystack.begin(),
        haystack.end(),
        needle.begin(),
        needle.end(),
        SameCharIgnoreCase) != haystack.end();
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

bool MatchesProbe(
    const WindowProbe& probe,
    std::wstring_view title,
    std::wstring_view class_name) {
    switch (probe.kind) {
    case WindowProbeKind::ClassName:
        return ContainsIgnoreCase(class_name, probe.value);
    case WindowProbeKind::WindowTitle:
        return ContainsIgnoreCase(title, probe.value);
    default:
        return false;
    }
}

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM parameter) {
    auto* state = reinterpret_cast<EnumerationState*>(parameter);
    ++state->visited_windows;

    if (hwnd == state->owner_window) {
        return TRUE;
    }

    const std::wstring title = WindowTitle(hwnd);
    const std::wstring class_name = WindowClassName(hwnd);

    for (const WindowProbe& probe : kDebuggerWindowProbes) {
        if (MatchesProbe(probe, title, class_name)) {
            state->match = {
                hwnd,
                probe,
                title,
                class_name,
                state->visited_windows
            };
            return FALSE;
        }
    }

    return TRUE;
}

std::wstring ErrorDetail(DWORD error) {
    std::wstringstream stream;
    stream << L"EnumWindows failed, GetLastError=" << error;
    return stream.str();
}

std::wstring MatchDetail(const WindowMatch& match) {
    std::wstringstream stream;
    stream
        << L"EnumWindows matched "
        << WindowProbeKindName(match.probe.kind)
        << L" probe \""
        << match.probe.value
        << L"\", HWND="
        << HwndHex(match.hwnd)
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

std::wstring_view NtUserBuildHwndListDebuggerWindowMechanism::Id() const noexcept {
    return L"nt_user_build_hwnd_list.debugger_window";
}

std::wstring_view NtUserBuildHwndListDebuggerWindowMechanism::Name() const noexcept {
    return L"NtUserBuildHwndList windows";
}

std::wstring_view NtUserBuildHwndListDebuggerWindowMechanism::Category() const noexcept {
    return L"NtUserBuildHwndList";
}

std::wstring_view NtUserBuildHwndListDebuggerWindowMechanism::Description() const noexcept {
    return L"Uses EnumWindows to inspect returned top-level window titles/classes for debugger indicators.";
}

MechanismResult NtUserBuildHwndListDebuggerWindowMechanism::Run(const MechanismContext& context) {
    EnumerationState state;
    state.owner_window = context.owner_window;

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
        L" top-level windows; no configured debugger title/class substring matched");
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::NtUserBuildHwndListDebuggerWindowMechanism>
    g_nt_user_build_hwnd_list_debugger_window_registrar;
}
