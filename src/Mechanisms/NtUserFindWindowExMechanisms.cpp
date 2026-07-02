#include "NtUserFindWindowExMechanisms.h"

#include "WindowProbeList.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>

#include <sstream>
#include <string>

namespace {

using adt::detail::HwndHex;
using adt::detail::WindowProbe;
using adt::detail::WindowProbeKind;
using adt::detail::WindowProbeKindName;
using adt::detail::kDebuggerWindowProbes;

struct ProbeMatch {
    HWND hwnd = nullptr;
    WindowProbe probe {};
};

HWND FindWindowByProbe(const WindowProbe& probe) {
    switch (probe.kind) {
    case WindowProbeKind::ClassName:
        return FindWindowExW(nullptr, nullptr, probe.value.data(), nullptr);
    case WindowProbeKind::WindowTitle:
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
        << WindowProbeKindName(match.probe.kind)
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
