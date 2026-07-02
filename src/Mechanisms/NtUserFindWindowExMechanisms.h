#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// Probes for debugger-related windows through FindWindowExW, which reaches the
// win32k NtUserFindWindowEx syscall under the normal Win32 API layer.
//
// What it observes:
// Some anti-debugging checks do not ask "am I being debugged?" directly. They
// ask whether well-known debugger UI windows exist on the current desktop. This
// mechanism performs a small set of direct window lookups using class names and
// window titles commonly associated with debuggers or RE tools.
//
// Why it matters:
// A non-null HWND means Windows found a window matching the requested class or
// exact title. That is a weak environmental signal: it may indicate x64dbg,
// WinDbg, IDA, or another tool is open, but it does not prove this process is
// attached to that debugger. It can also miss debuggers whose titles/classes are
// renamed, localized, version-specific, or hidden on a different desktop.
//
// API boundary:
// This row intentionally uses direct FindWindowExW probes. Broad "enumerate all
// windows and search for suspicious substrings" belongs to the later
// NtUserBuildHwndList/EnumWindows section. Keeping the two separate makes it
// easier to see which observable artifact each ScyllaHide hook is masking.
//
// ScyllaHide angle:
// ScyllaHide hooks NtUserFindWindowEx. After the real lookup succeeds, it checks
// whether the requested class or title contains debugger-related blacklist
// strings, and can return NULL instead of the real HWND.
class NtUserFindWindowExDebuggerWindowMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
