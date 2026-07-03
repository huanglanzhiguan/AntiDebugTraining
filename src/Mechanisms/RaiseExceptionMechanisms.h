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

}  // namespace adt
