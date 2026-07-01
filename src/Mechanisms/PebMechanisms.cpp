#include "PebMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>
#include <intrin.h>

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr std::uint32_t kNtGlobalFlagDebugBits = 0x70;
constexpr std::uint32_t kHeapDebugBits = 0x50000060;
constexpr std::uint32_t kProcessParametersImageKeyMissing = 0x4000;
constexpr std::uint32_t kMaxReasonableHeapCount = 1024;

#if defined(_M_X64)
constexpr std::size_t kPebBeingDebuggedOffset = 0x02;
constexpr std::size_t kPebProcessParametersOffset = 0x20;
constexpr std::size_t kPebNtGlobalFlagOffset = 0xBC;
constexpr std::size_t kPebNumberOfHeapsOffset = 0xE8;
constexpr std::size_t kPebProcessHeapsOffset = 0xF0;
constexpr std::size_t kHeapFlagsOffset = 0x70;
constexpr std::size_t kHeapForceFlagsOffset = 0x74;
constexpr std::size_t kProcessParametersFlagsOffset = 0x08;
constexpr std::size_t kProcessParametersStartingXOffset = 0x88;
constexpr std::size_t kProcessParametersStartingYOffset = 0x8C;
constexpr std::size_t kProcessParametersCountXOffset = 0x90;
constexpr std::size_t kProcessParametersCountYOffset = 0x94;
constexpr std::size_t kProcessParametersCountCharsXOffset = 0x98;
constexpr std::size_t kProcessParametersCountCharsYOffset = 0x9C;
constexpr std::size_t kProcessParametersFillAttributeOffset = 0xA0;
constexpr std::size_t kProcessParametersWindowFlagsOffset = 0xA4;
constexpr std::size_t kProcessParametersShowWindowFlagsOffset = 0xA8;
#elif defined(_M_IX86)
constexpr std::size_t kPebBeingDebuggedOffset = 0x02;
constexpr std::size_t kPebProcessParametersOffset = 0x10;
constexpr std::size_t kPebNtGlobalFlagOffset = 0x68;
constexpr std::size_t kPebNumberOfHeapsOffset = 0x88;
constexpr std::size_t kPebProcessHeapsOffset = 0x90;
constexpr std::size_t kHeapFlagsOffset = 0x40;
constexpr std::size_t kHeapForceFlagsOffset = 0x44;
constexpr std::size_t kProcessParametersFlagsOffset = 0x08;
constexpr std::size_t kProcessParametersStartingXOffset = 0x50;
constexpr std::size_t kProcessParametersStartingYOffset = 0x54;
constexpr std::size_t kProcessParametersCountXOffset = 0x58;
constexpr std::size_t kProcessParametersCountYOffset = 0x5C;
constexpr std::size_t kProcessParametersCountCharsXOffset = 0x60;
constexpr std::size_t kProcessParametersCountCharsYOffset = 0x64;
constexpr std::size_t kProcessParametersFillAttributeOffset = 0x68;
constexpr std::size_t kProcessParametersWindowFlagsOffset = 0x6C;
constexpr std::size_t kProcessParametersShowWindowFlagsOffset = 0x70;
#endif

std::uint8_t* CurrentPeb() {
#if defined(_M_X64)
    return reinterpret_cast<std::uint8_t*>(__readgsqword(0x60));
#elif defined(_M_IX86)
    return reinterpret_cast<std::uint8_t*>(__readfsdword(0x30));
#else
    return nullptr;
#endif
}

bool TryReadMemory(const void* address, void* value, std::size_t size) {
    SIZE_T bytes_read = 0;
    return ReadProcessMemory(
        GetCurrentProcess(),
        address,
        value,
        size,
        &bytes_read) == TRUE && bytes_read == size;
}

template <typename T>
bool TryReadField(const std::uint8_t* base, std::size_t offset, T* value) {
    if (base == nullptr) {
        return false;
    }

    return TryReadMemory(base + offset, value, sizeof(T));
}

std::wstring Hex32(std::uint32_t value) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

std::wstring StartupInfoDetails(
    std::uint32_t flags,
    std::uint32_t starting_x,
    std::uint32_t starting_y,
    std::uint32_t count_x,
    std::uint32_t count_y,
    std::uint32_t count_chars_x,
    std::uint32_t count_chars_y,
    std::uint32_t fill_attribute,
    std::uint32_t window_flags,
    std::uint32_t show_window_flags) {
    std::wstringstream stream;
    stream
        << L"Flags=" << Hex32(flags)
        << L", x=" << starting_x
        << L", y=" << starting_y
        << L", count=" << count_x << L"x" << count_y
        << L", chars=" << count_chars_x << L"x" << count_chars_y
        << L", fill=" << fill_attribute
        << L", flags=" << Hex32(window_flags)
        << L", show=" << show_window_flags;
    return stream.str();
}

bool HasSuspiciousStartupInfo(
    std::uint32_t starting_x,
    std::uint32_t starting_y,
    std::uint32_t count_x,
    std::uint32_t count_y,
    std::uint32_t count_chars_x,
    std::uint32_t count_chars_y,
    std::uint32_t fill_attribute) {
    return starting_x != 0 ||
        starting_y != 0 ||
        count_x != 0 ||
        count_y != 0 ||
        count_chars_x != 0 ||
        count_chars_y != 0 ||
        fill_attribute != 0;
}

}  // namespace

namespace adt {

std::wstring_view PebBeingDebuggedMechanism::Id() const noexcept {
    return L"peb.being_debugged";
}

std::wstring_view PebBeingDebuggedMechanism::Name() const noexcept {
    return L"PEB BeingDebugged";
}

std::wstring_view PebBeingDebuggedMechanism::Category() const noexcept {
    return L"PEB";
}

std::wstring_view PebBeingDebuggedMechanism::Description() const noexcept {
    return L"Reads the current process PEB BeingDebugged byte.";
}

MechanismResult PebBeingDebuggedMechanism::Run(const MechanismContext&) {
    const std::uint8_t* peb = CurrentPeb();
    if (peb == nullptr) {
        return MechanismResult::Error(L"unable to locate PEB");
    }

    std::uint8_t value = 0;
    if (!TryReadField(peb, kPebBeingDebuggedOffset, &value)) {
        return MechanismResult::Error(L"unable to read PEB BeingDebugged");
    }

    if (value != 0) {
        return MechanismResult::Detected(L"BeingDebugged=" + std::to_wstring(value));
    }

    return MechanismResult::Clean(L"BeingDebugged=0");
}

std::wstring_view PebNtGlobalFlagMechanism::Id() const noexcept {
    return L"peb.nt_global_flag";
}

std::wstring_view PebNtGlobalFlagMechanism::Name() const noexcept {
    return L"PEB NtGlobalFlag";
}

std::wstring_view PebNtGlobalFlagMechanism::Category() const noexcept {
    return L"PEB";
}

std::wstring_view PebNtGlobalFlagMechanism::Description() const noexcept {
    return L"Reads PEB NtGlobalFlag and checks debug heap bits.";
}

MechanismResult PebNtGlobalFlagMechanism::Run(const MechanismContext&) {
    const std::uint8_t* peb = CurrentPeb();
    if (peb == nullptr) {
        return MechanismResult::Error(L"unable to locate PEB");
    }

    std::uint32_t value = 0;
    if (!TryReadField(peb, kPebNtGlobalFlagOffset, &value)) {
        return MechanismResult::Error(L"unable to read PEB NtGlobalFlag");
    }

    const std::wstring detail = L"NtGlobalFlag=" + Hex32(value);

    if ((value & kNtGlobalFlagDebugBits) == kNtGlobalFlagDebugBits) {
        return MechanismResult::Detected(detail + L" debug heap bits set");
    }

    return MechanismResult::Clean(detail);
}

std::wstring_view PebHeapFlagsMechanism::Id() const noexcept {
    return L"peb.heap_flags";
}

std::wstring_view PebHeapFlagsMechanism::Name() const noexcept {
    return L"PEB process heap flags";
}

std::wstring_view PebHeapFlagsMechanism::Category() const noexcept {
    return L"PEB";
}

std::wstring_view PebHeapFlagsMechanism::Description() const noexcept {
    return L"Reads the process heap Flags and ForceFlags reached from the PEB.";
}

MechanismResult PebHeapFlagsMechanism::Run(const MechanismContext&) {
    const std::uint8_t* peb = CurrentPeb();
    if (peb == nullptr) {
        return MechanismResult::Error(L"unable to locate PEB");
    }

    std::uint32_t heap_count = 0;
    const std::uint8_t** heaps = nullptr;
    if (!TryReadField(peb, kPebNumberOfHeapsOffset, &heap_count) ||
        !TryReadField(peb, kPebProcessHeapsOffset, &heaps)) {
        return MechanismResult::Error(L"unable to read PEB heap metadata");
    }

    if (heap_count == 0 || heaps == nullptr) {
        return MechanismResult::Error(L"PEB heap metadata is not available");
    }

    if (heap_count > kMaxReasonableHeapCount) {
        return MechanismResult::Error(L"PEB NumberOfHeaps is unexpectedly large: " + std::to_wstring(heap_count));
    }

    std::vector<const std::uint8_t*> heap_addresses(heap_count);
    if (!TryReadMemory(heaps, heap_addresses.data(), heap_addresses.size() * sizeof(heap_addresses[0]))) {
        return MechanismResult::Error(L"unable to read PEB ProcessHeaps array");
    }

    std::wstringstream detail;
    detail << L"NumberOfHeaps=" << heap_count;

    for (std::uint32_t i = 0; i < heap_count; ++i) {
        const std::uint8_t* current_heap = heap_addresses[i];
        if (current_heap == nullptr) {
            return MechanismResult::Error(L"PEB ProcessHeaps contains a null heap pointer");
        }

        std::uint32_t flags = 0;
        std::uint32_t force_flags = 0;
        if (!TryReadField(current_heap, kHeapFlagsOffset, &flags) ||
            !TryReadField(current_heap, kHeapForceFlagsOffset, &force_flags)) {
            return MechanismResult::Error(L"unable to read process heap flags");
        }

        detail
            << L"; heap[" << i << L"] Flags=" << Hex32(flags)
            << L", ForceFlags=" << Hex32(force_flags);

        if ((flags & kHeapDebugBits) != 0 || (force_flags & kHeapDebugBits) != 0) {
            return MechanismResult::Detected(detail.str());
        }
    }

    return MechanismResult::Clean(detail.str());
}

std::wstring_view PebStartupInfoMechanism::Id() const noexcept {
    return L"peb.startup_info";
}

std::wstring_view PebStartupInfoMechanism::Name() const noexcept {
    return L"PEB StartupInfo";
}

std::wstring_view PebStartupInfoMechanism::Category() const noexcept {
    return L"PEB";
}

std::wstring_view PebStartupInfoMechanism::Description() const noexcept {
    return L"Reads selected startup-layout fields from RTL_USER_PROCESS_PARAMETERS.";
}

MechanismResult PebStartupInfoMechanism::Run(const MechanismContext&) {
    const std::uint8_t* peb = CurrentPeb();
    if (peb == nullptr) {
        return MechanismResult::Error(L"unable to locate PEB");
    }

    const std::uint8_t* parameters = nullptr;
    if (!TryReadField(peb, kPebProcessParametersOffset, &parameters)) {
        return MechanismResult::Error(L"unable to read PEB ProcessParameters");
    }

    if (parameters == nullptr) {
        return MechanismResult::Error(L"PEB ProcessParameters is null");
    }

    std::uint32_t flags = 0;
    std::uint32_t starting_x = 0;
    std::uint32_t starting_y = 0;
    std::uint32_t count_x = 0;
    std::uint32_t count_y = 0;
    std::uint32_t count_chars_x = 0;
    std::uint32_t count_chars_y = 0;
    std::uint32_t fill_attribute = 0;
    std::uint32_t window_flags = 0;
    std::uint32_t show_window_flags = 0;

    if (!TryReadField(parameters, kProcessParametersFlagsOffset, &flags) ||
        !TryReadField(parameters, kProcessParametersStartingXOffset, &starting_x) ||
        !TryReadField(parameters, kProcessParametersStartingYOffset, &starting_y) ||
        !TryReadField(parameters, kProcessParametersCountXOffset, &count_x) ||
        !TryReadField(parameters, kProcessParametersCountYOffset, &count_y) ||
        !TryReadField(parameters, kProcessParametersCountCharsXOffset, &count_chars_x) ||
        !TryReadField(parameters, kProcessParametersCountCharsYOffset, &count_chars_y) ||
        !TryReadField(parameters, kProcessParametersFillAttributeOffset, &fill_attribute) ||
        !TryReadField(parameters, kProcessParametersWindowFlagsOffset, &window_flags) ||
        !TryReadField(parameters, kProcessParametersShowWindowFlagsOffset, &show_window_flags)) {
        return MechanismResult::Error(L"unable to read PEB ProcessParameters startup fields");
    }

    const std::wstring detail = StartupInfoDetails(
        flags,
        starting_x,
        starting_y,
        count_x,
        count_y,
        count_chars_x,
        count_chars_y,
        fill_attribute,
        window_flags,
        show_window_flags);

    if (HasSuspiciousStartupInfo(
        starting_x,
        starting_y,
        count_x,
        count_y,
        count_chars_x,
        count_chars_y,
        fill_attribute)) {
        return MechanismResult::Detected(detail);
    }

    if ((flags & kProcessParametersImageKeyMissing) == 0) {
        return MechanismResult::Clean(detail + L" (IMAGE_KEY_MISSING not set)");
    }

    return MechanismResult::Clean(detail + L" (IMAGE_KEY_MISSING set)");
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::PebBeingDebuggedMechanism> g_peb_being_debugged_registrar;
const ::adt::MechanismRegistrar<::adt::PebNtGlobalFlagMechanism> g_peb_nt_global_flag_registrar;
const ::adt::MechanismRegistrar<::adt::PebHeapFlagsMechanism> g_peb_heap_flags_registrar;
const ::adt::MechanismRegistrar<::adt::PebStartupInfoMechanism> g_peb_startup_info_registrar;
}
