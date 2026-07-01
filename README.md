# AntiDebugTraining

AntiDebugTraining is an educational Windows reverse-engineering project for studying anti-debugging and anti-anti-debugging behavior in a controlled local lab.

The first phase follows anti-debugging mechanisms documented by ScyllaHide. For each mechanism, we will build a small, readable demonstration that shows what the program observes, how the result changes under a debugger, and how ScyllaHide affects that observation.

## Goals

- Study existing anti-debugging mechanisms described in `ScyllaHide.pdf`.
- Implement each anti-debugging mechanism as a separate class.
- Use a plugin-style design so mechanisms can be enabled or disabled independently.
- Build a UI that shows:
  - Which mechanisms are enabled.
  - Which mechanism is currently being tested.
  - The detection result for each mechanism.
  - A clear final status such as `debugger detected` or `clean`.

## Non-Goals

This project is not intended to create malware, hide from security tools, bypass protections in third-party software, or attack other systems.

The demos must avoid:

- Persistence.
- Privilege escalation.
- Credential access.
- Injection into unrelated processes.
- Network activity.
- Destructive behavior.
- Tampering with security products.

All examples should be safe local demonstrations of debugger-observable Windows artifacts.

## Phase 1: Anti-Debugging Training Program

The first artifact is a Windows program with a UI.

The program should contain multiple anti-debugging checks, but each check must be isolated behind a common mechanism interface. This lets students turn techniques on or off and observe each one independently.

Expected design direction:

- One class per anti-debugging mechanism.
- A shared interface for all mechanisms.
- A registry or plugin manager that discovers available mechanisms.
- UI controls for enabling and disabling mechanisms.
- A result panel showing each mechanism's output.

Example conceptual shape:

```text
AntiDebugTraining
  UI
  Mechanism Manager
  Mechanism Interface
  IsDebuggerPresent Check
  CheckRemoteDebuggerPresent Check
  NtQueryInformationProcess Check
  ...
```

We will not implement all mechanisms at once. Each mechanism should be added only after studying the corresponding ScyllaHide documentation section.

## Phase 2: Understanding Anti-Anti-Debugging

The original idea for the second step was to write an anti-anti-debug library.

Instead of reinventing that wheel, this project will use ScyllaHide itself as the reference implementation. The goal is to understand how ScyllaHide mitigates each technique and to verify those mitigations in the training program.

For each mechanism, the lab flow should be:

1. Run the program normally.
2. Run it under x64dbg.
3. Run it under x64dbg with ScyllaHide enabled.
4. Compare results.
5. Explain why the observable artifact changed or did not change.

## Phase 3: Advanced Research

Future work may explore advanced anti-debugging techniques and the limits of ScyllaHide.

This phase is intentionally deferred. Any advanced technique must be discussed first, scoped carefully, and kept educational, local, and non-destructive.

## Teaching Framework

Anti-debugging is not a random list of tricks. Each technique is an observation.

For every mechanism, the course notes should answer:

1. What is the program observing?
2. Why is that thing observable?
3. How reliable is the observation?
4. How can a reverse engineer hide, fake, patch, or avoid that observation?
5. What does this teach about Windows internals and debugging?

## Per-Mechanism Notes Format

Each ScyllaHide technique should be documented with this structure:

```text
Technique: <name>

1. What it checks
2. Why it works
3. Minimal demo code
4. How to test
5. What to observe in the debugger
6. How ScyllaHide likely mitigates it
7. Teaching notes
```

## Current Source Material

- `ScyllaHide.pdf`

We will go through this document section by section and add mechanisms only when they have been studied.

