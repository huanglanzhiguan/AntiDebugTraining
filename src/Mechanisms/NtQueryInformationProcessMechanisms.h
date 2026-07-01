#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// Queries ProcessDebugPort through NtQueryInformationProcess.
//
// What it observes:
// ProcessDebugPort asks the kernel whether the process has a debug port
// associated with it. For a normal non-debugged process, the returned value
// should be zero. A nonzero value is a direct user-mode debugger signal.
//
// Why it matters:
// This is one of the classic native API anti-debug checks and is stronger than
// process-list heuristics because it asks about the current process's debugger
// relationship rather than the surrounding environment. The documented
// CheckRemoteDebuggerPresent API uses this style of native query internally.
//
// ScyllaHide angle:
// ScyllaHide hooks NtQueryInformationProcess and forces ProcessDebugPort to a
// null value for the protected process.
class NtQueryProcessDebugPortMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

// Queries ProcessDebugFlags through NtQueryInformationProcess.
//
// What it observes:
// ProcessDebugFlags is historically inverted and easy to misread. A clean
// process normally reports a nonzero "no debug inherit" style value, while zero
// is commonly treated as debugger evidence. This mechanism marks zero as
// detected and includes the raw value in the details.
//
// Why it matters:
// The field reflects kernel-maintained debug inheritance/state rather than a PEB
// byte. It is therefore a useful companion to PEB.BeingDebugged and
// ProcessDebugPort when teaching that anti-debugging is a set of observations,
// not one magic flag.
//
// ScyllaHide angle:
// ScyllaHide returns a clean-looking ProcessDebugFlags value and also tracks
// related NtSetInformationProcess changes so the fake state remains consistent.
class NtQueryProcessDebugFlagsMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

// Queries ProcessDebugObjectHandle through NtQueryInformationProcess.
//
// What it observes:
// A debugger uses a kernel DebugObject to receive debug events. Querying
// ProcessDebugObjectHandle asks for a handle to the current process's debug
// object. In the clean case, Windows should report STATUS_PORT_NOT_SET and no
// usable handle. A successful query that returns a handle is strong debugger
// evidence; the demo closes that handle immediately to avoid leaking it.
//
// Why it matters:
// This is a direct debugger-object check. It is more precise than "is x64dbg.exe
// running" because it asks whether this process has an associated debug object.
// It also teaches why anti-anti-debug tools must preserve both return status and
// output-buffer semantics, not just overwrite one value.
//
// ScyllaHide angle:
// ScyllaHide returns STATUS_PORT_NOT_SET, writes a null handle, and preserves
// plausible ReturnLength behavior.
class NtQueryProcessDebugObjectHandleMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

// Queries ProcessBasicInformation through NtQueryInformationProcess and checks
// the inherited parent process ID.
//
// What it observes:
// PROCESS_BASIC_INFORMATION includes InheritedFromUniqueProcessId, the parent
// PID captured at process creation. This mechanism resolves that PID to a
// process image name with a toolhelp snapshot and checks the same small
// debugger-parent list used by the NtQuerySystemInformation parent check.
//
// Why it matters:
// This is another launch-lineage heuristic. It is strong when a debugger
// launched the target, but it does not prove that a debugger is currently
// attached. It is useful next to the SystemProcessInformation version because it
// shows two different APIs exposing the same lineage artifact.
//
// ScyllaHide angle:
// ScyllaHide hooks ProcessBasicInformation and rewrites
// InheritedFromUniqueProcessId to Explorer's PID for the current process.
class NtQueryProcessBasicInformationMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
