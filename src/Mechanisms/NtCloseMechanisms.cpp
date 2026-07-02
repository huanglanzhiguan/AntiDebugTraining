#include "NtCloseMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>

#include <cstdint>
#include <sstream>
#include <string>

namespace {

using NtCloseFn = LONG(NTAPI*)(HANDLE Handle);

constexpr LONG kStatusInvalidHandle = static_cast<LONG>(0xC0000008);
constexpr ULONG_PTR kInvalidHandleValue = 0x1337;

struct NtCloseProbeResult {
    LONG status = 0;
    DWORD exception_code = 0;
    bool returned = false;
    bool exception_caught = false;
};

FARPROC ResolveNativeRoutine(const char* name) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        ntdll = LoadLibraryW(L"ntdll.dll");
    }

    if (ntdll == nullptr) {
        return nullptr;
    }

    return GetProcAddress(ntdll, name);
}

NtCloseFn ResolveNtClose() {
    return reinterpret_cast<NtCloseFn>(ResolveNativeRoutine("NtClose"));
}

std::wstring Hex32(std::uint32_t value) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

std::wstring StatusHex(LONG status) {
    return Hex32(static_cast<std::uint32_t>(status));
}

std::wstring HandleHex(ULONG_PTR value) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

NtCloseProbeResult ProbeInvalidHandle(NtCloseFn nt_close) noexcept {
    NtCloseProbeResult result;

    __try {
        result.status = nt_close(reinterpret_cast<HANDLE>(kInvalidHandleValue));
        result.returned = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result.exception_caught = true;
        result.exception_code = GetExceptionCode();
    }

    return result;
}

}  // namespace

namespace adt {

std::wstring_view NtCloseInvalidHandleMechanism::Id() const noexcept {
    return L"nt_close.invalid_handle_exception";
}

std::wstring_view NtCloseInvalidHandleMechanism::Name() const noexcept {
    return L"NtClose invalid handle";
}

std::wstring_view NtCloseInvalidHandleMechanism::Category() const noexcept {
    return L"NtClose";
}

std::wstring_view NtCloseInvalidHandleMechanism::Description() const noexcept {
    return L"Calls NtClose with an invalid handle and watches for EXCEPTION_INVALID_HANDLE.";
}

bool NtCloseInvalidHandleMechanism::SupportsLiveMode() const noexcept {
    return false;
}

MechanismResult NtCloseInvalidHandleMechanism::Run(const MechanismContext&) {
    const NtCloseFn nt_close = ResolveNtClose();
    if (nt_close == nullptr) {
        return MechanismResult::Error(L"NtClose is unavailable");
    }

    const NtCloseProbeResult probe = ProbeInvalidHandle(nt_close);
    const std::wstring handle_text = HandleHex(kInvalidHandleValue);

    if (probe.exception_caught) {
        const std::wstring detail =
            L"NtClose(" + handle_text + L") raised exception " +
            Hex32(probe.exception_code);

        if (probe.exception_code == EXCEPTION_INVALID_HANDLE) {
            return MechanismResult::Detected(
                detail + L"; invalid-handle exception reached the process handler");
        }

        return MechanismResult::Error(detail + L"; unexpected exception code");
    }

    const std::wstring detail =
        L"NtClose(" + handle_text + L") returned Status=" +
        StatusHex(probe.status) +
        L"; no invalid-handle exception reached the process handler";

    if (probe.returned && probe.status == kStatusInvalidHandle) {
        return MechanismResult::Clean(detail);
    }

    return MechanismResult::Clean(detail + L" (unexpected status, but no debugger-style exception)");
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::NtCloseInvalidHandleMechanism> g_ntclose_invalid_handle_registrar;
}
