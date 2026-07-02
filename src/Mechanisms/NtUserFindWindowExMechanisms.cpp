#include "NtUserFindWindowExMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>

namespace {

enum class ProbeKind {
    ClassName,
    WindowTitle
};

struct WindowProbe {
    ProbeKind kind;
    std::wstring_view value;
};

struct ProbeMatch {
    HWND hwnd = nullptr;
    WindowProbe probe {};
};

// This list mirrors the teaching idea in ScyllaHide rather than trying to be a
// complete product-grade signature set. A short list is easier to reason about
// in the debugger and keeps false positives visible during the lab.
constexpr std::array<WindowProbe, 20> kDebuggerWindowProbes = {{
    { ProbeKind::WindowTitle, L"OLLYDBG" },
    { ProbeKind::WindowTitle, L"ida" },
    { ProbeKind::WindowTitle, L"disassembly" },
    { ProbeKind::WindowTitle, L"scylla" },
    { ProbeKind::WindowTitle, L"Debug" },
    { ProbeKind::WindowTitle, L"[CPU" },
    { ProbeKind::WindowTitle, L"WinDbg" },
    { ProbeKind::WindowTitle, L"x32dbg" },
    { ProbeKind::WindowTitle, L"x64dbg" },
    { ProbeKind::WindowTitle, L"Cheat Engine" },
    { ProbeKind::ClassName, L"OLLYDBG" },
    { ProbeKind::ClassName, L"WinDbgFrameClass" },
    { ProbeKind::ClassName, L"DbgX.Shell" },
    { ProbeKind::ClassName, L"idawindow" },
    { ProbeKind::ClassName, L"tnavbox" },
    { ProbeKind::ClassName, L"idaview" },
    { ProbeKind::ClassName, L"tgrzoom" },
    { ProbeKind::ClassName, L"PROCMON_WINDOW_CLASS" },
    { ProbeKind::ClassName, L"APIMonitor By Rohitab" },
    { ProbeKind::ClassName, L"99929D61-1338-48B1-9433-D42A1D94F0D2" },
}};

const wchar_t* ProbeKindName(ProbeKind kind) noexcept {
    switch (kind) {
    case ProbeKind::ClassName:
        return L"class";
    case ProbeKind::WindowTitle:
        return L"title";
    default:
        return L"unknown";
    }
}

std::wstring HwndHex(HWND hwnd) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase
           << reinterpret_cast<std::uintptr_t>(hwnd);
    return stream.str();
}

HWND FindWindowByProbe(const WindowProbe& probe) {
    switch (probe.kind) {
    case ProbeKind::ClassName:
        return FindWindowExW(nullptr, nullptr, probe.value.data(), nullptr);
    case ProbeKind::WindowTitle:
        return FindWindowExW(nullptr, nullptr, nullptr, probe.value.data());
    default:
        return nullptr;
    }
}

ProbeMatch FindFirstDebuggerWindowProbe() {
    for (const WindowProbe& probe : kDebuggerWindowProbes) {
        if (HWND hwnd = FindWindowByProbe(probe)) {
            return { hwnd, probe };
        }
    }

    return {};
}

std::wstring ProbeDetail(const ProbeMatch& match) {
    std::wstringstream stream;
    stream
        << L"FindWindowExW matched "
        << ProbeKindName(match.probe.kind)
        << L" probe \""
        << match.probe.value
        << L"\", HWND="
        << HwndHex(match.hwnd);
    return stream.str();
}

}  // namespace

namespace adt {

std::wstring_view NtUserFindWindowExDebuggerWindowMechanism::Id() const noexcept {
    return L"nt_user_find_window_ex.debugger_window";
}

std::wstring_view NtUserFindWindowExDebuggerWindowMechanism::Name() const noexcept {
    return L"NtUserFindWindowEx window";
}

std::wstring_view NtUserFindWindowExDebuggerWindowMechanism::Category() const noexcept {
    return L"NtUserFindWindowEx";
}

std::wstring_view NtUserFindWindowExDebuggerWindowMechanism::Description() const noexcept {
    return L"Uses FindWindowExW to probe for known debugger-related window classes and titles.";
}

MechanismResult NtUserFindWindowExDebuggerWindowMechanism::Run(const MechanismContext&) {
    const ProbeMatch match = FindFirstDebuggerWindowProbe();
    if (match.hwnd != nullptr) {
        return MechanismResult::Detected(ProbeDetail(match));
    }

    return MechanismResult::Clean(
        L"FindWindowExW did not find any configured debugger window class/title probes");
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::NtUserFindWindowExDebuggerWindowMechanism>
    g_nt_user_find_window_ex_debugger_window_registrar;
}
