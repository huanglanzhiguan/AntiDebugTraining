#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// Calls NtClose with an intentionally invalid handle and observes whether the
// close failure is delivered as a user-mode exception.
//
// What it observes:
// Windows handle values are meaningful only inside the current process handle
// table. Passing a made-up value such as 0x1337 to NtClose should fail because
// there is no matching kernel handle table entry. When no debugger or close
// exception diagnostic is active, the native API normally just returns
// STATUS_INVALID_HANDLE.
//
// Why it matters:
// CloseHandle/NtClose have special diagnostic behavior when a process is being
// debugged: invalid or pseudo handles can raise EXCEPTION_INVALID_HANDLE
// instead of only returning an error status. A protected program can wrap the
// call in SEH and treat that exception reaching the program as evidence that a
// debugger changed the normal error-delivery path.
//
// Why trigger-only:
// The check deliberately performs an invalid operation to study debugger
// exception routing. It is safe and local, but it should run only when the
// student clicks Check instead of on every UI refresh.
//
// ScyllaHide angle:
// ScyllaHide hooks NtClose, validates the handle first with NtQueryObject, and
// returns STATUS_INVALID_HANDLE directly for invalid handles. That avoids the
// real kernel path that would raise a debugger-visible invalid-handle
// exception.
class NtCloseInvalidHandleMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    bool SupportsLiveMode() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
