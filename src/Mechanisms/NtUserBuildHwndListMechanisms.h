#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// Enumerates top-level windows through EnumWindows, which reaches the win32k
// NtUserBuildHwndList syscall under the normal Win32 API layer.
//
// What it observes:
// Instead of asking for one exact class/title as FindWindowEx does, this
// mechanism asks Windows for the current top-level HWND list and inspects the
// actual title and class name of each returned window. It then applies a small
// debugger/RE-tool blacklist using case-insensitive substring matching.
//
// Why it matters:
// This is a broader environmental observation. A matching window can show that
// x64dbg, WinDbg, IDA, or a related tool is open in the same desktop/session,
// even when that tool is not attached to this process. It is therefore useful
// to strict protectors, but noisy: renamed tools, alternate desktops, hidden
// windows, unrelated titles containing words like "Debug", and normal developer
// tooling can all affect the result.
//
// Self-window handling:
// ScyllaHide's sample blacklist includes broad substrings such as "Debug", so
// this mechanism deliberately skips the owner HWND before matching. That keeps
// the lab focused on outside tool windows instead of detecting itself every
// live refresh if the visible title changes later.
//
// ScyllaHide angle:
// ScyllaHide hooks NtUserBuildHwndList and filters bad HWND entries out of the
// list returned to EnumWindows/EnumThreadWindows callers. When the hook works,
// the callback should never receive the debugger window HWND.
class NtUserBuildHwndListDebuggerWindowMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
