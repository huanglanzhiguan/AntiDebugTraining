#pragma once

#include <array>
#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>

#include <Windows.h>

namespace adt::detail {

enum class WindowProbeKind {
    ClassName,
    WindowTitle
};

struct WindowProbe {
    WindowProbeKind kind;
    std::wstring_view value;
};

// ScyllaHide uses blacklist-style matching for debugger/RE tool window text and
// class names. This intentionally compact list is enough for the course labs
// without pretending to be a complete commercial signature set. We omit very
// broad title terms such as "Debug", "scylla", "ida", and "disassembly" because
// normal development tools, paths, and source file names can otherwise dominate
// the training signal.
inline constexpr std::array<WindowProbe, 16> kDebuggerWindowProbes = {{
    { WindowProbeKind::WindowTitle, L"OLLYDBG" },
    { WindowProbeKind::WindowTitle, L"x64dbg" },
    { WindowProbeKind::WindowTitle, L"x32dbg" },
    { WindowProbeKind::WindowTitle, L"WinDbg" },
    { WindowProbeKind::WindowTitle, L"Cheat Engine" },
    { WindowProbeKind::WindowTitle, L"[CPU" },
    { WindowProbeKind::ClassName, L"OLLYDBG" },
    { WindowProbeKind::ClassName, L"WinDbgFrameClass" },
    { WindowProbeKind::ClassName, L"DbgX.Shell" },
    { WindowProbeKind::ClassName, L"idawindow" },
    { WindowProbeKind::ClassName, L"tnavbox" },
    { WindowProbeKind::ClassName, L"idaview" },
    { WindowProbeKind::ClassName, L"tgrzoom" },
    { WindowProbeKind::ClassName, L"PROCMON_WINDOW_CLASS" },
    { WindowProbeKind::ClassName, L"APIMonitor By Rohitab" },
    { WindowProbeKind::ClassName, L"99929D61-1338-48B1-9433-D42A1D94F0D2" },
}};

inline const wchar_t* WindowProbeKindName(WindowProbeKind kind) noexcept {
    switch (kind) {
    case WindowProbeKind::ClassName:
        return L"class";
    case WindowProbeKind::WindowTitle:
        return L"title";
    default:
        return L"unknown";
    }
}

inline std::wstring HwndHex(HWND hwnd) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase
           << reinterpret_cast<std::uintptr_t>(hwnd);
    return stream.str();
}

}  // namespace adt::detail
