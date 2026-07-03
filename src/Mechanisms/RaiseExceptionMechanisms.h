#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// Raises STATUS_BREAKPOINT through RaiseException.
//
// What it observes:
// STATUS_BREAKPOINT is the classic software-breakpoint exception code. Raising
// it explicitly does not patch an INT3 byte into the program, but it still uses
// the same debugger-visible exception code that debuggers normally care about.
//
// Why it matters:
// Compared with DBG_PRINTEXCEPTION_C, this variant is less like a debug-output
// channel and more likely to visibly stop in x64dbg. If the debugger consumes
// the exception and resumes execution, RaiseException returns and the target can
// treat that as evidence of debugger intervention. If the exception is passed
// to the program, the SEH handler runs and the row reports clean.
//
// ScyllaHide angle:
// ScyllaHide's exception settings include a Breakpoint option. The lab should
// compare x64dbg's normal handling with ScyllaHide configured to pass/fake this
// exception behavior.
//
// Teaching note:
// ScyllaHide's documentation also lists DBG_PRINTEXCEPTION_C, but x64dbg often
// handles that as debug-output plumbing without visibly breaking. This training
// row uses STATUS_BREAKPOINT because students can directly compare pass vs.
// swallow behavior in the debugger.
class RaiseExceptionBreakpointMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    bool SupportsLiveMode() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

// Installs a top-level unhandled exception filter and raises STATUS_BREAKPOINT.
//
// What it observes:
// SetUnhandledExceptionFilter registers a process-wide last-chance filter. This
// filter is reached only after an exception has not been handled by vectored or
// frame-based handlers. In a normal non-debugged run, a continuable software
// breakpoint raised by RaiseException can reach that top-level filter, and the
// filter can return EXCEPTION_CONTINUE_EXECUTION.
//
// Why it matters:
// A debugger gets first chance at the exception before the application's normal
// dispatch path. If the debugger consumes the breakpoint, RaiseException returns
// without the top-level filter running. If Windows' own unhandled-exception path
// still observes the process as debugged, the custom filter may also be skipped
// and the exception is routed back to the debugger as a later-chance event.
//
// ScyllaHide angle:
// This is not just a one-API return-value hook. A mitigation has to make the
// debugger's exception policy and the debugged-state checks line up with what a
// non-debugged process would see.
//
// Teaching note:
// This row deliberately differs from RaiseExceptionBreakpointMechanism. The
// RaiseException row asks whether a nearby __except block received the exception;
// this row asks whether the exception survived to the process-level top filter.
class UnhandledExceptionFilterBreakpointMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    bool SupportsLiveMode() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
