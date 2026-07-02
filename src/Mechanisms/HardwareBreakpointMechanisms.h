#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// Reads the current thread's CPU debug-register context through
// NtGetContextThread.
//
// What it observes:
// Hardware breakpoints are stored in per-thread CPU debug registers. DR0-DR3
// hold breakpoint addresses, DR6 reports debug status, and DR7 enables and
// configures the breakpoint slots. Debuggers use these registers for hardware
// execute/access/write breakpoints because they do not require patching code
// bytes with an INT3 instruction.
//
// Why it matters:
// A protected program can ask Windows for a thread CONTEXT with
// CONTEXT_DEBUG_REGISTERS. Nonzero DR0-DR3 or enabled DR7 breakpoint slots are
// strong evidence that someone configured hardware breakpoints for that thread.
// This is thread-local state, so the lab should set the hardware breakpoint on
// the same thread that runs the Check action.
//
// Why trigger-only:
// The mechanism is read-only, but it is still a deliberate debugger-state probe
// and its result is easiest to understand when the student triggers it after
// setting or clearing a hardware breakpoint.
//
// ScyllaHide angle:
// ScyllaHide hooks NtGetContextThread and removes CONTEXT_DEBUG_REGISTERS from
// the real query, then restores the requested ContextFlags while returning
// zeroed DR0-DR7 values. Related hooks on NtSetContextThread,
// KiUserExceptionDispatcher, and NtContinue prevent the target from clearing
// hardware breakpoints while hiding them from exception contexts.
class HardwareBreakpointDrxMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    bool SupportsLiveMode() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
