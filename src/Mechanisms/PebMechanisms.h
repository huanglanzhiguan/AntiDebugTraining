#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// Reads the BeingDebugged byte from the current process PEB.
//
// What it observes:
// The PEB is user-mode process metadata that ntdll and the loader keep mapped
// into every process. The BeingDebugged byte is set by Windows when a process is
// created under a user-mode debugger or when debugger state is attached in the
// usual way.
//
// Why it matters:
// The classic IsDebuggerPresent API is essentially a documented wrapper around
// this artifact, so reading the PEB directly avoids an API call that can be
// hooked or breakpointed. A nonzero value is a direct, high-confidence debugger
// signal, but it is also one of the easiest artifacts for anti-anti-debug tools
// to patch.
//
// ScyllaHide angle:
// ScyllaHide can write this PEB byte back to zero inside the debuggee. In the
// lab, the row should turn red under a debugger and return to clean when the PEB
// BeingDebugged mitigation is active.
class PebBeingDebuggedMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

// Reads the NtGlobalFlag field from the current process PEB.
//
// What it observes:
// NtGlobalFlag contains process-wide diagnostic flags. When a process is
// started with heap debugging, verifier, or certain GFlags settings, Windows may
// set heap validation bits such as tail checking, free checking, and parameter
// validation. These bits are commonly summarized as the 0x70 debug heap mask.
//
// Why it matters:
// A normal process usually does not have the full debug heap mask set. If these
// bits are present, the process was likely created in a diagnostic/debug heap
// environment. This is not the same as "a debugger is attached right now"; it is
// an observation of process creation and heap instrumentation state.
//
// ScyllaHide angle:
// ScyllaHide clears the debug heap bits from the PEB field so direct PEB reads
// see a normal-looking NtGlobalFlag value.
class PebNtGlobalFlagMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

// Walks the process heap array from the PEB and checks each heap's Flags and
// ForceFlags fields for debug heap bits.
//
// What it observes:
// The PEB points to the process heap list. Individual heap structures contain
// flags that reflect heap validation features such as tail checking, free
// checking, skipped validation checks, and parameter validation. These fields
// are implementation details, so this mechanism uses known offsets for the
// target architecture and reads defensively.
//
// Why it matters:
// Debug heap flags can remain visible even if a simple PEB NtGlobalFlag check is
// hidden. This gives protectors a second view of the same broad artifact:
// process heap diagnostics. Like NtGlobalFlag, it is strongest when the process
// was launched with debugging/verifier settings rather than merely attached to
// later.
//
// ScyllaHide angle:
// ScyllaHide masks the heap debug bits in heap Flags and ForceFlags so a direct
// heap walk sees ordinary heap state.
class PebHeapFlagsMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

// Reads selected RTL_USER_PROCESS_PARAMETERS startup-layout fields through the
// PEB ProcessParameters pointer.
//
// What it observes:
// STARTUPINFO values supplied to CreateProcess are copied into the process
// parameters block. Unusual window position, size, character count, or fill
// attributes can reveal that a custom launcher or protector/debugger workflow
// created the process with non-default startup metadata.
//
// Why it matters:
// This is a launch-context heuristic, not a direct debugger-state check. A
// benign launcher can set these fields, and a debugger can launch without
// setting them. It is still useful educationally because it shows that process
// creation leaves user-mode artifacts outside the obvious BeingDebugged byte.
//
// ScyllaHide angle:
// ScyllaHide normalizes selected ProcessParameters startup fields and may set
// IMAGE_KEY_MISSING-style flags to make the block look closer to ordinary
// Explorer-launched process state.
class PebStartupInfoMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
