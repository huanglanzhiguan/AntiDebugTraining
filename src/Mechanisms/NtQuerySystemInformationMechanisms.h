#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// Queries SystemKernelDebuggerInformation through NtQuerySystemInformation.
//
// What it observes:
// This asks Windows for global kernel-debugger state. The returned structure
// includes KernelDebuggerEnabled and KernelDebuggerNotPresent. A kernel debugger
// is different from a normal user-mode debugger such as x64dbg, so this row is
// usually clean in a user-mode-only lab.
//
// Why it matters:
// Some protectors care whether the whole OS is being kernel-debugged because a
// kernel debugger can observe or modify user-mode behavior from outside the
// process. This is a direct-ish signal for kernel debugging, but not a direct
// signal for "x64dbg is attached to this process."
//
// ScyllaHide angle:
// ScyllaHide's NtQuerySystemInformation hook forces the returned values toward
// "kernel debugger not present" for this information class.
class NtQuerySystemKernelDebuggerMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

// Queries SystemProcessInformation and checks the current process parent.
//
// What it observes:
// SystemProcessInformation returns a snapshot of the system process table,
// including each process ID, image name, and inherited parent PID. This
// mechanism finds the current process, resolves its parent entry from the same
// snapshot, and compares the parent image name with a small debugger-parent
// list such as x64dbg.exe, ida64.exe, and windbg.exe.
//
// Why it matters:
// Parent process lineage is a launch-context heuristic. If x64dbg launched the
// target, parent PID == x64dbg.exe is strong evidence of an analyst-controlled
// run. It is not a direct attach relationship: attaching later does not change
// the parent PID, and a debugger can detach after launching.
//
// ScyllaHide angle:
// When the NtQuerySystemInformation hook is active, ScyllaHide rewrites the
// current process entry so InheritedFromUniqueProcessId looks like Explorer's
// PID. This row is a good demonstration that ScyllaHide profile options matter:
// the mitigation only works if this hook is enabled.
class NtQuerySystemParentProcessMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
