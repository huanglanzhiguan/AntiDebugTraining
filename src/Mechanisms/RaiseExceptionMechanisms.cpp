#include "RaiseExceptionMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>

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

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::RaiseExceptionBreakpointMechanism> g_raise_exception_breakpoint_registrar;
}
