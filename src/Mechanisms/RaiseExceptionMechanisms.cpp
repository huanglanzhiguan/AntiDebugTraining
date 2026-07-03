#include "RaiseExceptionMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <sstream>
#include <string>

namespace {

constexpr DWORD kStatusBreakpoint = 0x80000003;

struct RaiseExceptionProbeResult {
    bool handler_ran = false;
    bool raise_returned = false;
    DWORD exception_code = 0;
};

struct UnhandledExceptionProbeResult {
    bool filter_ran = false;
    bool raise_returned = false;
    DWORD exception_code = 0;
};

struct UnhandledExceptionProbeState {
    std::atomic_bool active = false;
    std::atomic_bool filter_ran = false;
    std::atomic<DWORD> exception_code = 0;
    std::atomic<DWORD> thread_id = 0;
};

UnhandledExceptionProbeState g_unhandled_exception_probe;

std::wstring Hex32(std::uint32_t value) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

RaiseExceptionProbeResult ProbeException(DWORD code_to_raise) noexcept {
    RaiseExceptionProbeResult result;

    __try {
        RaiseException(code_to_raise, 0, 0, nullptr);
        result.raise_returned = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result.handler_ran = true;
        result.exception_code = GetExceptionCode();
    }

    return result;
}

LONG WINAPI ProbeUnhandledExceptionFilter(EXCEPTION_POINTERS* exception_info) noexcept {
    if (!g_unhandled_exception_probe.active.load(std::memory_order_acquire)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (g_unhandled_exception_probe.thread_id.load(std::memory_order_relaxed) != GetCurrentThreadId()) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (exception_info == nullptr || exception_info->ExceptionRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const DWORD exception_code = exception_info->ExceptionRecord->ExceptionCode;
    g_unhandled_exception_probe.exception_code.store(exception_code, std::memory_order_release);

    if (exception_code != kStatusBreakpoint) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    g_unhandled_exception_probe.filter_ran.store(true, std::memory_order_release);
    return EXCEPTION_CONTINUE_EXECUTION;
}

UnhandledExceptionProbeResult ProbeUnhandledExceptionFilter() noexcept {
    UnhandledExceptionProbeResult result;

    const LPTOP_LEVEL_EXCEPTION_FILTER previous_filter =
        SetUnhandledExceptionFilter(ProbeUnhandledExceptionFilter);
    const UINT old_error_mode = GetErrorMode();
    SetErrorMode(old_error_mode | SEM_NOGPFAULTERRORBOX);

    g_unhandled_exception_probe.filter_ran.store(false, std::memory_order_release);
    g_unhandled_exception_probe.exception_code.store(0, std::memory_order_release);
    g_unhandled_exception_probe.thread_id.store(GetCurrentThreadId(), std::memory_order_release);
    g_unhandled_exception_probe.active.store(true, std::memory_order_release);

    RaiseException(kStatusBreakpoint, 0, 0, nullptr);
    result.raise_returned = true;

    g_unhandled_exception_probe.active.store(false, std::memory_order_release);
    g_unhandled_exception_probe.thread_id.store(0, std::memory_order_release);

    result.filter_ran = g_unhandled_exception_probe.filter_ran.load(std::memory_order_acquire);
    result.exception_code = g_unhandled_exception_probe.exception_code.load(std::memory_order_acquire);

    SetUnhandledExceptionFilter(previous_filter);
    SetErrorMode(old_error_mode);

    return result;
}

adt::MechanismResult ResultFromProbe(
    const wchar_t* api_name,
    DWORD expected_exception,
    const RaiseExceptionProbeResult& probe) {
    const std::wstring exception_text = Hex32(expected_exception);

    if (probe.handler_ran) {
        const std::wstring detail =
            std::wstring(api_name) + L"(" + exception_text + L") reached handler with code " +
            Hex32(probe.exception_code);

        if (probe.exception_code == expected_exception) {
            return adt::MechanismResult::Clean(detail);
        }

        return adt::MechanismResult::Error(detail + L"; unexpected exception code");
    }

    if (probe.raise_returned) {
        return adt::MechanismResult::Detected(
            std::wstring(api_name) + L"(" + exception_text +
            L") returned without handler; exception was likely consumed by the debugger");
    }

    return adt::MechanismResult::Error(
        std::wstring(api_name) + L"(" + exception_text + L") neither reached handler nor returned");
}

adt::MechanismResult ResultFromUnhandledFilterProbe(const UnhandledExceptionProbeResult& probe) {
    const std::wstring exception_text = Hex32(kStatusBreakpoint);

    if (probe.filter_ran) {
        const std::wstring detail =
            L"top-level filter received STATUS_BREAKPOINT with code " + Hex32(probe.exception_code);

        if (probe.exception_code == kStatusBreakpoint) {
            return adt::MechanismResult::Clean(detail);
        }

        return adt::MechanismResult::Error(detail + L"; unexpected exception code");
    }

    if (probe.raise_returned) {
        return adt::MechanismResult::Detected(
            L"RaiseException(" + exception_text +
            L") returned without reaching the top-level unhandled exception filter");
    }

    return adt::MechanismResult::Error(
        L"RaiseException(" + exception_text + L") neither reached the top-level filter nor returned");
}

}  // namespace

namespace adt {

std::wstring_view RaiseExceptionBreakpointMechanism::Id() const noexcept {
    return L"raise_exception.breakpoint";
}

std::wstring_view RaiseExceptionBreakpointMechanism::Name() const noexcept {
    return L"RaiseException BREAKPOINT";
}

std::wstring_view RaiseExceptionBreakpointMechanism::Category() const noexcept {
    return L"Raise Exception";
}

std::wstring_view RaiseExceptionBreakpointMechanism::Description() const noexcept {
    return L"Raises STATUS_BREAKPOINT and checks whether SEH receives it.";
}

bool RaiseExceptionBreakpointMechanism::SupportsLiveMode() const noexcept {
    return false;
}

MechanismResult RaiseExceptionBreakpointMechanism::Run(const MechanismContext&) {
    return ResultFromProbe(
        L"RaiseException",
        kStatusBreakpoint,
        ProbeException(kStatusBreakpoint));
}

std::wstring_view UnhandledExceptionFilterBreakpointMechanism::Id() const noexcept {
    return L"unhandled_exception_filter.breakpoint";
}

std::wstring_view UnhandledExceptionFilterBreakpointMechanism::Name() const noexcept {
    return L"UnhandledExceptionFilter";
}

std::wstring_view UnhandledExceptionFilterBreakpointMechanism::Category() const noexcept {
    return L"Exceptions";
}

std::wstring_view UnhandledExceptionFilterBreakpointMechanism::Description() const noexcept {
    return L"Raises STATUS_BREAKPOINT and checks whether the process top-level filter runs.";
}

bool UnhandledExceptionFilterBreakpointMechanism::SupportsLiveMode() const noexcept {
    return false;
}

MechanismResult UnhandledExceptionFilterBreakpointMechanism::Run(const MechanismContext&) {
    return ResultFromUnhandledFilterProbe(ProbeUnhandledExceptionFilter());
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::RaiseExceptionBreakpointMechanism> g_raise_exception_breakpoint_registrar;
const ::adt::MechanismRegistrar<::adt::UnhandledExceptionFilterBreakpointMechanism>
    g_unhandled_exception_filter_breakpoint_registrar;
}
