#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// Maps top-level windows back to their owning processes through
// GetWindowThreadProcessId, which reaches the win32k NtUserQueryWindow syscall
// under the normal Win32 API layer.
//
// What it observes:
// Windows tracks the GUI thread that owns every HWND, and that thread belongs
// to a process. This mechanism enumerates top-level windows, asks Windows for
// each window's owner thread/process IDs, then compares the owner process image
// name against a focused debugger-process list.
//
// Why it matters:
// This detects a different relationship than title/class matching. A window can
// have a harmless title but still belong to x64dbg.exe, WinDbg, IDA, or another
// debugger. The observable chain is HWND -> thread -> process -> image name.
// That makes it a useful companion to NtUserFindWindowEx and
// NtUserBuildHwndList, but it is still environmental: it proves a debugger-like
// process owns a window in the desktop/session, not necessarily that the current
// process is attached to it.
//
// Lab isolation:
// To test ScyllaHide's NtUserQueryWindow hook by itself, keep the
// NtUserFindWindowEx and NtUserBuildHwndList hooks disabled. If those hooks hide
// the debugger HWND first, this mechanism may never get a window handle whose
// owner needs to be queried.
//
// ScyllaHide angle:
// ScyllaHide hooks NtUserQueryWindow. When a queried HWND is considered bad, it
// returns the protected process/thread IDs instead of the debugger's real owner
// IDs, making GetWindowThreadProcessId report a benign-looking owner.
class NtUserQueryWindowOwnerProcessMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
