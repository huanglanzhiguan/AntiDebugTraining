#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// Queries ntdll's current-process heap debug buffer with
// RtlQueryProcessHeapInformation.
//
// What it observes:
// RtlCreateQueryDebugBuffer allocates an RTL debug-information buffer, and
// RtlQueryProcessHeapInformation fills the buffer's RTL_PROCESS_HEAPS summary
// for the current process. The classic anti-debug sample inspects the first
// heap's RTL_HEAP_INFORMATION::Flags field. Debug-heap creation can set
// validation bits such as tail checking, free checking, skipped validation, or
// parameter validation.
//
// Why it matters:
// This is mostly the same artifact as the PEB process-heap walk, but reached
// through an ntdll helper API instead of manual structure walking. That makes it
// valuable for teaching access paths: if an anti-anti-debug tool only patches a
// direct PEB read, this API surface can still leak the original heap flags. This
// row intentionally uses the first heap as the detection signal to match the
// published technique and avoid false positives from auxiliary heaps.
//
// ScyllaHide angle:
// ScyllaHide-style mitigation can either normalize the underlying heap fields or
// hook this API and adjust RTL_PROCESS_HEAPS::Heaps[n].Flags in the returned
// buffer. Check Point's mitigation notes describe setting the reported heap
// Flags back to HEAP_GROWABLE.
class RtlQueryProcessHeapInformationMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    bool SupportsLiveMode() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

// Queries ntdll's process debug-information helper for our own PID.
//
// What it observes:
// RtlQueryProcessDebugInformation can collect several kinds of process debug
// information. With the heap flags enabled, it asks ntdll to populate the same
// RTL_PROCESS_HEAPS-style summary used by RtlQueryProcessHeapInformation. This
// row requests heap summaries and heap blocks, matching the classic published
// anti-debug example.
//
// Why it matters:
// This demonstrates a slightly more general query surface. The signal is still
// heap-debug instrumentation, not a new "debugger attached now" fact. It is most
// useful when the process was launched under a debugger or with debug heap
// settings, and it can stay clean if the debugger attaches later.
//
// ScyllaHide angle:
// A mitigation can hook RtlQueryProcessDebugInformation or normalize the heap
// data that this function eventually reads. Students should compare this row
// against the direct PEB heap row to see whether both surfaces agree.
class RtlQueryProcessDebugInformationMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    bool SupportsLiveMode() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
