#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// Demonstrates the ProcessHandleTracing class of NtSetInformationProcess.
//
// What it observes:
// ProcessHandleTracing is a diagnostic mode that records handle operations for a
// process. Debuggers, Application Verifier, GFlags-style diagnostics, or a
// program itself can enable this mode. Querying ProcessHandleTracing before this
// demo enables it tells us whether that diagnostic state was already present.
//
// Why it matters:
// This is a side-channel check. It does not prove a debugger is attached, but it
// can reveal that the process is running under handle-tracing instrumentation.
// The implementation is trigger-only because it briefly enables and disables
// tracing on the current process to demonstrate the set/query behavior without
// continuously changing process state.
//
// Safety boundary:
// The same ScyllaHide documentation section also mentions
// ProcessBreakOnTermination, which can mark a process critical and cause a BSOD
// on termination. This training mechanism intentionally does not set that class.
//
// ScyllaHide angle:
// ScyllaHide hooks NtSetInformationProcess and NtQueryInformationProcess so
// ProcessHandleTracing state can be shadowed/faked consistently rather than
// exposing the real diagnostic state.
class NtSetProcessHandleTracingMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    bool SupportsLiveMode() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
