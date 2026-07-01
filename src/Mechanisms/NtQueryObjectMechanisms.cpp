#include "NtQueryObjectMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace {

using NtQueryObjectFn = LONG(NTAPI*)(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength);

using NtCreateDebugObjectFn = LONG(NTAPI*)(
    PHANDLE DebugObjectHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    ULONG Flags);

constexpr ULONG kObjectTypeInformation = 2;
constexpr ULONG kObjectTypesInformation = 3;
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004);
constexpr LONG kStatusBufferOverflow = static_cast<LONG>(0x80000005);
constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023);
constexpr ULONG kInitialObjectBufferSize = 64 * 1024;
constexpr ULONG kMaximumObjectBufferSize = 4 * 1024 * 1024;
constexpr ACCESS_MASK kDebugAllAccess = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xF;

struct NativeUnicodeString {
    USHORT length;
    USHORT maximum_length;
    PWSTR buffer;
};

struct ObjectTypeInformation {
    NativeUnicodeString type_name;
    ULONG total_number_of_objects;
    ULONG total_number_of_handles;
    ULONG total_paged_pool_usage;
    ULONG total_non_paged_pool_usage;
    ULONG total_name_pool_usage;
    ULONG total_handle_table_usage;
    ULONG high_water_number_of_objects;
    ULONG high_water_number_of_handles;
    ULONG high_water_paged_pool_usage;
    ULONG high_water_non_paged_pool_usage;
    ULONG high_water_name_pool_usage;
    ULONG high_water_handle_table_usage;
    ULONG invalid_attributes;
    GENERIC_MAPPING generic_mapping;
    ULONG valid_access_mask;
    BOOLEAN security_required;
    BOOLEAN maintain_handle_count;
    UCHAR type_index;
    CHAR reserved_byte;
    ULONG pool_type;
    ULONG default_paged_pool_charge;
    ULONG default_non_paged_pool_charge;
};

struct ObjectTypesInformation {
    ULONG number_of_types;
    ObjectTypeInformation type_information[1];
};

struct DebugObjectCounts {
    bool found = false;
    ULONG total_objects = 0;
    ULONG total_handles = 0;
};

struct ObjectQueryBuffer {
    LONG status = 0;
    ULONG return_length = 0;
    std::vector<std::uint8_t> buffer;
};

bool NtSuccess(LONG status) {
    return status >= 0;
}

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

NtQueryObjectFn ResolveNtQueryObject() {
    return reinterpret_cast<NtQueryObjectFn>(ResolveNativeRoutine("NtQueryObject"));
}

NtCreateDebugObjectFn ResolveNtCreateDebugObject() {
    return reinterpret_cast<NtCreateDebugObjectFn>(ResolveNativeRoutine("NtCreateDebugObject"));
}

std::wstring Hex32(std::uint32_t value) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

std::wstring StatusHex(LONG status) {
    return Hex32(static_cast<std::uint32_t>(status));
}

std::size_t AlignUp(std::size_t value, std::size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

bool IsResizeStatus(LONG status) {
    return status == kStatusInfoLengthMismatch ||
        status == kStatusBufferOverflow ||
        status == kStatusBufferTooSmall;
}

std::wstring TypeName(const ObjectTypeInformation* info) {
    if (info->type_name.length == 0 || info->type_name.buffer == nullptr) {
        return L"";
    }

    return std::wstring(
        info->type_name.buffer,
        info->type_name.length / sizeof(wchar_t));
}

ObjectQueryBuffer QueryObjectInformation(
    NtQueryObjectFn query_object,
    HANDLE handle,
    ULONG information_class) {
    ObjectQueryBuffer result;
    result.buffer.resize(kInitialObjectBufferSize);

    for (;;) {
        result.return_length = 0;
        result.status = query_object(
            handle,
            information_class,
            result.buffer.data(),
            static_cast<ULONG>(result.buffer.size()),
            &result.return_length);

        if (!IsResizeStatus(result.status)) {
            break;
        }

        const ULONG requested_size = result.return_length != 0
            ? result.return_length + (16 * 1024)
            : static_cast<ULONG>(result.buffer.size() * 2);

        if (requested_size > kMaximumObjectBufferSize ||
            result.buffer.size() >= kMaximumObjectBufferSize) {
            break;
        }

        result.buffer.resize(requested_size);
    }

    return result;
}

DebugObjectCounts FindDebugObjectCounts(const std::vector<std::uint8_t>& buffer) {
    DebugObjectCounts counts;
    const auto* types = reinterpret_cast<const ObjectTypesInformation*>(buffer.data());
    const auto* current = types->type_information;

    for (ULONG i = 0; i < types->number_of_types; ++i) {
        const std::wstring type_name = TypeName(current);
        if (type_name == L"DebugObject") {
            counts.found = true;
            counts.total_objects = current->total_number_of_objects;
            counts.total_handles = current->total_number_of_handles;
            return counts;
        }

        const auto* after_fixed_fields = reinterpret_cast<const std::uint8_t*>(current + 1);
        const std::size_t aligned_name_size = AlignUp(current->type_name.maximum_length, sizeof(void*));
        current = reinterpret_cast<const ObjectTypeInformation*>(after_fixed_fields + aligned_name_size);
    }

    return counts;
}

DebugObjectCounts CountsFromObjectTypeInformation(const std::vector<std::uint8_t>& buffer) {
    const auto* info = reinterpret_cast<const ObjectTypeInformation*>(buffer.data());
    return {
        TypeName(info) == L"DebugObject",
        info->total_number_of_objects,
        info->total_number_of_handles
    };
}

std::wstring CountsDetail(
    const std::wstring& prefix,
    const DebugObjectCounts& counts,
    LONG status,
    ULONG return_length) {
    std::wstringstream stream;
    stream
        << prefix
        << L" Status=" << StatusHex(status)
        << L", DebugObjectFound=" << (counts.found ? 1 : 0)
        << L", TotalNumberOfObjects=" << counts.total_objects
        << L", TotalNumberOfHandles=" << counts.total_handles
        << L", ReturnLength=" << return_length;
    return stream.str();
}

}  // namespace

namespace adt {

std::wstring_view NtQueryObjectTypesDebugObjectMechanism::Id() const noexcept {
    return L"nt_query_object.object_types_debug_object";
}

std::wstring_view NtQueryObjectTypesDebugObjectMechanism::Name() const noexcept {
    return L"NtQO ObjectTypes DebugObject";
}

std::wstring_view NtQueryObjectTypesDebugObjectMechanism::Category() const noexcept {
    return L"NtQueryObject";
}

std::wstring_view NtQueryObjectTypesDebugObjectMechanism::Description() const noexcept {
    return L"Queries ObjectTypesInformation and checks global DebugObject object/handle counts.";
}

MechanismResult NtQueryObjectTypesDebugObjectMechanism::Run(const MechanismContext&) {
    const auto query_object = ResolveNtQueryObject();
    if (query_object == nullptr) {
        return MechanismResult::Error(L"NtQueryObject is unavailable");
    }

    const ObjectQueryBuffer query = QueryObjectInformation(
        query_object,
        nullptr,
        kObjectTypesInformation);

    if (!NtSuccess(query.status)) {
        return MechanismResult::Error(
            L"Status=" + StatusHex(query.status) +
            L", ReturnLength=" + std::to_wstring(query.return_length));
    }

    const DebugObjectCounts counts = FindDebugObjectCounts(query.buffer);
    const std::wstring detail = CountsDetail(L"ObjectTypesInformation", counts, query.status, query.return_length);

    if (counts.found && (counts.total_objects != 0 || counts.total_handles != 0)) {
        return MechanismResult::Detected(detail);
    }

    return MechanismResult::Clean(detail);
}

std::wstring_view NtQueryObjectTypeDebugObjectMechanism::Id() const noexcept {
    return L"nt_query_object.object_type_debug_object";
}

std::wstring_view NtQueryObjectTypeDebugObjectMechanism::Name() const noexcept {
    return L"NtQO ObjectType DebugObject";
}

std::wstring_view NtQueryObjectTypeDebugObjectMechanism::Category() const noexcept {
    return L"NtQueryObject";
}

std::wstring_view NtQueryObjectTypeDebugObjectMechanism::Description() const noexcept {
    return L"Creates a temporary DebugObject and queries its ObjectTypeInformation counts.";
}

bool NtQueryObjectTypeDebugObjectMechanism::SupportsLiveMode() const noexcept {
    return false;
}

MechanismResult NtQueryObjectTypeDebugObjectMechanism::Run(const MechanismContext&) {
    const auto query_object = ResolveNtQueryObject();
    const auto create_debug_object = ResolveNtCreateDebugObject();
    if (query_object == nullptr || create_debug_object == nullptr) {
        return MechanismResult::Error(L"NtQueryObject or NtCreateDebugObject is unavailable");
    }

    HANDLE debug_object = nullptr;
    const LONG create_status = create_debug_object(
        &debug_object,
        kDebugAllAccess,
        nullptr,
        0);

    if (!NtSuccess(create_status) || debug_object == nullptr) {
        return MechanismResult::Error(L"NtCreateDebugObject Status=" + StatusHex(create_status));
    }

    const ObjectQueryBuffer query = QueryObjectInformation(
        query_object,
        debug_object,
        kObjectTypeInformation);

    CloseHandle(debug_object);

    if (!NtSuccess(query.status)) {
        return MechanismResult::Error(
            L"NtQueryObject Status=" + StatusHex(query.status) +
            L", NtCreateDebugObject Status=" + StatusHex(create_status) +
            L", ReturnLength=" + std::to_wstring(query.return_length));
    }

    const DebugObjectCounts counts = CountsFromObjectTypeInformation(query.buffer);
    const std::wstring detail =
        CountsDetail(L"ObjectTypeInformation", counts, query.status, query.return_length) +
        L", NtCreateDebugObject Status=" + StatusHex(create_status);

    if (!counts.found) {
        return MechanismResult::Error(detail + L" (queried object type was not DebugObject)");
    }

    if (counts.total_objects > 1 || counts.total_handles > 1) {
        return MechanismResult::Detected(detail + L" (more than our temporary DebugObject)");
    }

    return MechanismResult::Clean(detail);
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::NtQueryObjectTypesDebugObjectMechanism> g_ntqo_object_types_debug_object_registrar;
const ::adt::MechanismRegistrar<::adt::NtQueryObjectTypeDebugObjectMechanism> g_ntqo_object_type_debug_object_registrar;
}
