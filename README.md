# AntiDebugTraining

AntiDebugTraining is a native Windows C++ training program for learning how common anti-debugging checks observe debugger-visible artifacts.

The project is intentionally educational and non-destructive. It is meant for a controlled local reverse-engineering lab with tools such as Visual Studio, x64dbg, and ScyllaHide.

## What This Project Demonstrates

Anti-debugging is treated as a set of observations, not as a bag of tricks. Each mechanism asks:

1. What is the program observing?
2. Why is that artifact observable on Windows?
3. When does the artifact indicate a debugger?
4. How reliable is the signal?
5. How can a reverse engineer hide, fake, patch, or avoid the observation?

The UI shows each mechanism, its category, whether it is a live or trigger check, the current result, details, and the last check time.

Result states are deliberately simple:

- `debugger detected`
- `clean`
- error or not-run states when a check cannot complete

## Scope

This program focuses on safe local detection demos. It does not implement payloads, persistence, injection into unrelated processes, privilege escalation, credential access, network activity, or security-tool tampering.

Some anti-debugging ideas are intentionally left out of this UI because they are destructive, crash-prone, too debugger-workflow-specific, or better taught as standalone lab programs.

## Building

Open `AntiDebugTraining.sln` in Visual Studio and build the `x64` configuration.

The project is a Win32 desktop application using C++17.

A command-line build can also be run with MSBuild:

```powershell
MSBuild AntiDebugTraining.sln /p:Configuration=Debug /p:Platform=x64 /m
```

## Running The Lab

Typical workflow:

1. Run the program normally.
2. Run or attach with x64dbg.
3. Run or attach with x64dbg and ScyllaHide enabled.
4. Compare the row details and final status.
5. Explain which Windows artifact changed, which did not, and why.

Live rows are polled while enabled. Trigger rows run only when their `Check` button is clicked.

## Implemented Mechanism Areas

The current app includes beginner-friendly checks in these categories:

- PEB and process-heap artifacts
- `NtSetInformationProcess`
- `NtQuerySystemInformation`
- `NtQueryInformationProcess`
- `NtQueryObject`
- debugger-related window discovery
- debugger-window owner process checks
- `NtClose` invalid-handle exception behavior
- hardware breakpoint register checks
- explicit exception-routing checks
- `UnhandledExceptionFilter`
- RTL heap debug-information APIs

These mechanisms cover the core beginner lessons:

- Debugger state can appear in user-mode process structures.
- Native APIs can expose debugger-related process state.
- Object handles and debug objects leak useful context.
- Debugger UI/process artifacts can be detected from another process.
- Exception delivery differs depending on debugger policy.
- Hardware breakpoints are visible through debug registers unless hidden.
- Some checks are launch-time artifacts rather than live attach detectors.

## Important Testing Notes

Not every check should turn red when a debugger attaches later.

For example, PEB heap flags and RTL heap debug-information checks are mostly launch-time or debug-heap artifacts. They may stay clean when x64dbg attaches to an already-running process, but turn red when the process is launched under a debugger or diagnostic heap configuration.

Window-based checks may detect an open debugger even if the debugger has not attached yet, unless ScyllaHide is injected into the target and configured to hide those windows.

Exception-based checks depend heavily on debugger exception policy. In x64dbg, pass/swallow behavior can change whether the program's handler sees an exception.

## Architecture

Each anti-debugging technique is implemented as a class behind a shared mechanism interface:

- `src/Core/IAntiDebugMechanism.h`
- `src/Core/MechanismRegistry.h`
- `src/App/MainWindow.h`
- `src/Mechanisms/*`

Each mechanism provides:

- stable ID
- display name
- category
- description
- live or trigger execution mode
- one focused `Run` implementation

Mechanisms self-register through `MechanismRegistrar`, so the UI can discover and display them without hardcoding each row in the main window.

## Source Material

The initial mechanism set was developed while studying ScyllaHide's documentation and behavior. The project also cross-references public anti-debugging technique catalogs, especially for process-memory and exception-routing topics.

Reference material used during development:

- `ScyllaHide.pdf`
- ScyllaHide source code
- Check Point Anti-Debug techniques

## Advanced Work

Future advanced demos should probably live outside this beginner UI. Good standalone lab candidates include:

- software breakpoint byte scanning
- anti-step-over return-address checks
- code checksum and patch detection
- TLS callback timing
- working-set / copy-on-write memory checks
- memory-breakpoint and guard-page behavior

Keeping those as separate programs makes it easier to demonstrate fragile runtime behavior without making the main training UI crash-prone or confusing.
