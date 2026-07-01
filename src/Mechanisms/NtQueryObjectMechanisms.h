#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// Queries ObjectTypesInformation through NtQueryObject and inspects the global
// DebugObject type counters.
//
// What it observes:
// The Windows object manager tracks kernel object types such as Process, Thread,
// File, Event, and DebugObject. ObjectTypesInformation returns a variable-length
// list of these types. Each type entry includes global counters like
// TotalNumberOfObjects and TotalNumberOfHandles. This mechanism walks the list,
// finds the DebugObject entry, and treats nonzero counts as debugger evidence.
//
// Why it matters:
// User-mode debugging relies on DebugObject instances so the debugger can
// receive debug events. Seeing DebugObject counts can reveal debugging activity
// even without calling a process-specific debug query. The tradeoff is noise:
// these are global type counters, so unrelated debugger activity elsewhere on
// the machine can affect the result.
//
// ScyllaHide angle:
// ScyllaHide filters ObjectTypesInformation and zeroes DebugObject object/handle
// counts to hide this system-wide artifact.
class NtQueryObjectTypesDebugObjectMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

// Creates a temporary local DebugObject and queries its ObjectTypeInformation.
//
// What it observes:
// ObjectTypeInformation reports information for the object type behind a
// specific handle. To ask for DebugObject type counters, the program needs a
// DebugObject handle. This trigger creates one local temporary debug object,
// queries the type information, then closes the handle.
//
// Why it matters:
// The expected baseline is not zero because the demo itself created one
// DebugObject. Counts greater than our temporary object/handle suggest other
// DebugObject state exists, often because a debugger is active. This is still a
// global counter heuristic, not a perfect proof that this exact process is
// currently debugged.
//
// Why trigger-only:
// The row intentionally creates temporary local state, so it should run only
// when the student clicks Check. The object is closed immediately after the
// query and no other process is touched.
//
// ScyllaHide angle:
// ScyllaHide filters ObjectTypeInformation by subtracting the debugger's
// DebugObject counts while preserving plausible counts for objects created by
// the program itself.
class NtQueryObjectTypeDebugObjectMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    bool SupportsLiveMode() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
