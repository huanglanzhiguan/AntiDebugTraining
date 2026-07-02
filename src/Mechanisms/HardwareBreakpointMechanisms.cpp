#include "HardwareBreakpointMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>

#include <cstdint>
#include <sstream>
#include <string>

namespace {

using NtGetContextThreadFn = LONG(NTAPI*)(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext);

constexpr DWORD_PTR kDr7BreakpointEnableMask = 0xFF;

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

NtGetContextThreadFn ResolveNtGetContextThread() {
    return reinterpret_cast<NtGetContextThreadFn>(
        ResolveNativeRoutine("NtGetContextThread"));
}

std::wstring Hex32(std::uint32_t value) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

std::wstring StatusHex(LONG status) {
    return Hex32(static_cast<std::uint32_t>(status));
}

std::wstring HexRegister(DWORD_PTR value) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

bool NtSuccess(LONG status) {
    return status >= 0;
}

bool HasActiveHardwareBreakpoint(const CONTEXT& context) {
    return context.Dr0 != 0 ||
        context.Dr1 != 0 ||
        context.Dr2 != 0 ||
        context.Dr3 != 0 ||
        (context.Dr7 & kDr7BreakpointEnableMask) != 0;
}

std::wstring DrxDetail(LONG status, const CONTEXT& context) {
    std::wstringstream stream;
    stream
        << L"NtGetContextThread Status=" << StatusHex(status)
        << L", TID=" << GetCurrentThreadId()
        << L", DR0=" << HexRegister(static_cast<DWORD_PTR>(context.Dr0))
        << L", DR1=" << HexRegister(static_cast<DWORD_PTR>(context.Dr1))
        << L", DR2=" << HexRegister(static_cast<DWORD_PTR>(context.Dr2))
        << L", DR3=" << HexRegister(static_cast<DWORD_PTR>(context.Dr3))
        << L", DR6=" << HexRegister(static_cast<DWORD_PTR>(context.Dr6))
        << L", DR7=" << HexRegister(static_cast<DWORD_PTR>(context.Dr7));
    return stream.str();
}

}  // namespace

namespace adt {

std::wstring_view HardwareBreakpointDrxMechanism::Id() const noexcept {
    return L"hardware_breakpoint.drx_context";
}

std::wstring_view HardwareBreakpointDrxMechanism::Name() const noexcept {
    return L"NtGetContextThread DRx";
}

std::wstring_view HardwareBreakpointDrxMechanism::Category() const noexcept {
    return L"Hardware Breakpoint";
}

std::wstring_view HardwareBreakpointDrxMechanism::Description() const noexcept {
    return L"Reads current-thread DR0-DR3, DR6, and DR7 with NtGetContextThread.";
}

bool HardwareBreakpointDrxMechanism::SupportsLiveMode() const noexcept {
    return false;
}

MechanismResult HardwareBreakpointDrxMechanism::Run(const MechanismContext&) {
    const NtGetContextThreadFn nt_get_context_thread = ResolveNtGetContextThread();
    if (nt_get_context_thread == nullptr) {
        return MechanismResult::Error(L"NtGetContextThread is unavailable");
    }

    CONTEXT context = {};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    const LONG status = nt_get_context_thread(GetCurrentThread(), &context);
    const std::wstring detail = DrxDetail(status, context);

    if (!NtSuccess(status)) {
        return MechanismResult::Error(detail);
    }

    if (HasActiveHardwareBreakpoint(context)) {
        return MechanismResult::Detected(
            detail + L"; active hardware breakpoint state is visible");
    }

    return MechanismResult::Clean(
        detail + L"; no active hardware breakpoint state is visible");
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::HardwareBreakpointDrxMechanism> g_hardware_breakpoint_drx_registrar;
}
