#include "RtlDebugApiMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <Windows.h>

#include <cstdint>
#include <sstream>
#include <string>

namespace {

using NtStatus = LONG;

constexpr NtStatus kStatusSuccess = 0;
constexpr ULONG kPdiHeaps = 0x00000004;
constexpr ULONG kPdiHeapBlocks = 0x00000010;
constexpr ULONG kDebugInformationHeapFlags = kPdiHeaps | kPdiHeapBlocks;
constexpr ULONG kHeapGrowable = 0x00000002;
constexpr ULONG kHeapTailChecking = 0x00000020;
constexpr ULONG kHeapFreeChecking = 0x00000040;
constexpr ULONG kHeapSkipValidationChecks = 0x10000000;
constexpr ULONG kHeapValidateParameters = 0x40000000;
constexpr ULONG kHeapDebugBits =
    kHeapTailChecking | kHeapFreeChecking | kHeapSkipValidationChecks | kHeapValidateParameters;
constexpr ULONG kMaxReasonableHeapCount = 4096;

struct RtlHeapInformation {
    PVOID BaseAddress;
    ULONG Flags;
    USHORT EntryOverhead;
    USHORT CreatorBackTraceIndex;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    ULONG NumberOfTags;
    ULONG NumberOfEntries;
    ULONG NumberOfPseudoTags;
    ULONG PseudoTagGranularity;
    ULONG Reserved[5];
    PVOID Tags;
    PVOID Entries;
};

struct RtlProcessHeaps {
    ULONG NumberOfHeaps;
    RtlHeapInformation Heaps[1];
};

struct RtlDebugInformation {
    HANDLE SectionHandleClient;
    PVOID ViewBaseClient;
    PVOID ViewBaseTarget;
    ULONG_PTR ViewBaseDelta;
    HANDLE EventPairClient;
    HANDLE EventPairTarget;
    HANDLE TargetProcessId;
    HANDLE TargetThreadHandle;
    ULONG Flags;
    SIZE_T OffsetFree;
    SIZE_T CommitSize;
    SIZE_T ViewSize;
    PVOID Modules;
    PVOID BackTraces;
    RtlProcessHeaps* Heaps;
    PVOID Locks;
    PVOID SpecificHeap;
    HANDLE TargetProcessHandle;
    PVOID VerifierOptions;
    PVOID ProcessHeap;
    HANDLE CriticalSectionHandle;
    HANDLE CriticalSectionOwnerThread;
    PVOID Reserved[4];
};

using RtlCreateQueryDebugBufferFn = RtlDebugInformation*(NTAPI*)(ULONG maximum_commit, BOOLEAN use_event_pair);
using RtlDestroyQueryDebugBufferFn = NtStatus(NTAPI*)(RtlDebugInformation* buffer);
using RtlQueryProcessHeapInformationFn = NtStatus(NTAPI*)(RtlDebugInformation* buffer);
using RtlQueryProcessDebugInformationFn =
    NtStatus(NTAPI*)(HANDLE unique_process_id, ULONG flags, RtlDebugInformation* buffer);

struct RtlApiSet {
    RtlCreateQueryDebugBufferFn create_buffer = nullptr;
    RtlDestroyQueryDebugBufferFn destroy_buffer = nullptr;
    RtlQueryProcessHeapInformationFn query_heap_information = nullptr;
    RtlQueryProcessDebugInformationFn query_debug_information = nullptr;
};

bool NtSuccess(NtStatus status) {
    return status >= kStatusSuccess;
}

std::wstring Hex32(std::uint32_t value) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

RtlApiSet LoadRtlApis() {
    RtlApiSet apis;

    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return apis;
    }

    apis.create_buffer = reinterpret_cast<RtlCreateQueryDebugBufferFn>(
        GetProcAddress(ntdll, "RtlCreateQueryDebugBuffer"));
    apis.destroy_buffer = reinterpret_cast<RtlDestroyQueryDebugBufferFn>(
        GetProcAddress(ntdll, "RtlDestroyQueryDebugBuffer"));
    apis.query_heap_information = reinterpret_cast<RtlQueryProcessHeapInformationFn>(
        GetProcAddress(ntdll, "RtlQueryProcessHeapInformation"));
    apis.query_debug_information = reinterpret_cast<RtlQueryProcessDebugInformationFn>(
        GetProcAddress(ntdll, "RtlQueryProcessDebugInformation"));

    return apis;
}

class RtlDebugBuffer final {
public:
    explicit RtlDebugBuffer(const RtlApiSet& apis) : apis_(apis) {
        if (apis_.create_buffer != nullptr) {
            buffer_ = apis_.create_buffer(0, FALSE);
        }
    }

    RtlDebugBuffer(const RtlDebugBuffer&) = delete;
    RtlDebugBuffer& operator=(const RtlDebugBuffer&) = delete;

    ~RtlDebugBuffer() {
        if (buffer_ != nullptr && apis_.destroy_buffer != nullptr) {
            apis_.destroy_buffer(buffer_);
        }
    }

    RtlDebugInformation* get() const noexcept {
        return buffer_;
    }

private:
    const RtlApiSet& apis_;
    RtlDebugInformation* buffer_ = nullptr;
};

adt::MechanismResult ApiUnavailableResult(const wchar_t* api_name) {
    return adt::MechanismResult::Error(std::wstring(api_name) + L" is unavailable");
}

adt::MechanismResult InspectHeapBuffer(
    const wchar_t* api_name,
    NtStatus status,
    const RtlDebugInformation* buffer) {
    if (!NtSuccess(status)) {
        return adt::MechanismResult::Error(
            std::wstring(api_name) + L" failed with NTSTATUS=" + Hex32(static_cast<std::uint32_t>(status)));
    }

    if (buffer == nullptr || buffer->Heaps == nullptr) {
        return adt::MechanismResult::Error(std::wstring(api_name) + L" returned no heap information");
    }

    const RtlProcessHeaps* process_heaps = buffer->Heaps;
    const ULONG heap_count = process_heaps->NumberOfHeaps;
    if (heap_count == 0) {
        return adt::MechanismResult::Error(std::wstring(api_name) + L" returned zero heaps");
    }

    if (heap_count > kMaxReasonableHeapCount) {
        return adt::MechanismResult::Error(
            std::wstring(api_name) + L" returned an unexpectedly large heap count: " +
            std::to_wstring(heap_count));
    }

    std::wstringstream detail;
    detail
        << api_name
        << L" status=" << Hex32(static_cast<std::uint32_t>(status))
        << L", NumberOfHeaps=" << heap_count;

    const ULONG first_heap_flags = process_heaps->Heaps[0].Flags;
    const ULONG first_heap_debug_bits = first_heap_flags & kHeapDebugBits;
    const ULONG first_heap_non_growable_bits = first_heap_flags & ~kHeapGrowable;
    ULONG auxiliary_debug_heap_count = 0;

    for (ULONG i = 0; i < heap_count; ++i) {
        const ULONG flags = process_heaps->Heaps[i].Flags;
        const ULONG debug_bits = flags & kHeapDebugBits;
        const ULONG non_growable_bits = flags & ~kHeapGrowable;

        detail
            << L"; heap[" << i << L"] Base=" << process_heaps->Heaps[i].BaseAddress
            << L", Flags=" << Hex32(flags)
            << L", DebugBits=" << Hex32(debug_bits)
            << L", NonGrowableBits=" << Hex32(non_growable_bits);

        if (i != 0 && debug_bits != 0) {
            ++auxiliary_debug_heap_count;
        }
    }

    detail
        << L"; first heap signal Flags=" << Hex32(first_heap_flags)
        << L", DebugBits=" << Hex32(first_heap_debug_bits)
        << L", NonGrowableBits=" << Hex32(first_heap_non_growable_bits);

    if (auxiliary_debug_heap_count != 0) {
        detail
            << L"; ignored auxiliary heaps with debug bits="
            << auxiliary_debug_heap_count;
    }

    if (first_heap_debug_bits != 0) {
        return adt::MechanismResult::Detected(detail.str());
    }

    return adt::MechanismResult::Clean(detail.str());
}

adt::MechanismResult RunRtlQueryProcessHeapInformation() {
    const RtlApiSet apis = LoadRtlApis();
    if (apis.create_buffer == nullptr) {
        return ApiUnavailableResult(L"RtlCreateQueryDebugBuffer");
    }

    if (apis.destroy_buffer == nullptr) {
        return ApiUnavailableResult(L"RtlDestroyQueryDebugBuffer");
    }

    if (apis.query_heap_information == nullptr) {
        return ApiUnavailableResult(L"RtlQueryProcessHeapInformation");
    }

    RtlDebugBuffer buffer(apis);
    if (buffer.get() == nullptr) {
        return adt::MechanismResult::Error(L"RtlCreateQueryDebugBuffer returned null");
    }

    const NtStatus status = apis.query_heap_information(buffer.get());
    return InspectHeapBuffer(L"RtlQueryProcessHeapInformation", status, buffer.get());
}

adt::MechanismResult RunRtlQueryProcessDebugInformation() {
    const RtlApiSet apis = LoadRtlApis();
    if (apis.create_buffer == nullptr) {
        return ApiUnavailableResult(L"RtlCreateQueryDebugBuffer");
    }

    if (apis.destroy_buffer == nullptr) {
        return ApiUnavailableResult(L"RtlDestroyQueryDebugBuffer");
    }

    if (apis.query_debug_information == nullptr) {
        return ApiUnavailableResult(L"RtlQueryProcessDebugInformation");
    }

    RtlDebugBuffer buffer(apis);
    if (buffer.get() == nullptr) {
        return adt::MechanismResult::Error(L"RtlCreateQueryDebugBuffer returned null");
    }

    const HANDLE current_pid = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(GetCurrentProcessId()));
    const NtStatus status =
        apis.query_debug_information(current_pid, kDebugInformationHeapFlags, buffer.get());
    return InspectHeapBuffer(L"RtlQueryProcessDebugInformation", status, buffer.get());
}

}  // namespace

namespace adt {

std::wstring_view RtlQueryProcessHeapInformationMechanism::Id() const noexcept {
    return L"rtl.query_process_heap_information";
}

std::wstring_view RtlQueryProcessHeapInformationMechanism::Name() const noexcept {
    return L"RtlQueryProcessHeapInformation";
}

std::wstring_view RtlQueryProcessHeapInformationMechanism::Category() const noexcept {
    return L"RTL Debug APIs";
}

std::wstring_view RtlQueryProcessHeapInformationMechanism::Description() const noexcept {
    return L"Uses ntdll's RTL debug buffer to inspect current-process heap flags.";
}

bool RtlQueryProcessHeapInformationMechanism::SupportsLiveMode() const noexcept {
    return false;
}

MechanismResult RtlQueryProcessHeapInformationMechanism::Run(const MechanismContext&) {
    return RunRtlQueryProcessHeapInformation();
}

std::wstring_view RtlQueryProcessDebugInformationMechanism::Id() const noexcept {
    return L"rtl.query_process_debug_information";
}

std::wstring_view RtlQueryProcessDebugInformationMechanism::Name() const noexcept {
    return L"RtlQueryProcessDebugInformation";
}

std::wstring_view RtlQueryProcessDebugInformationMechanism::Category() const noexcept {
    return L"RTL Debug APIs";
}

std::wstring_view RtlQueryProcessDebugInformationMechanism::Description() const noexcept {
    return L"Uses ntdll's process debug-information query to inspect heap flags for this PID.";
}

bool RtlQueryProcessDebugInformationMechanism::SupportsLiveMode() const noexcept {
    return false;
}

MechanismResult RtlQueryProcessDebugInformationMechanism::Run(const MechanismContext&) {
    return RunRtlQueryProcessDebugInformation();
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::RtlQueryProcessHeapInformationMechanism>
    g_rtl_query_process_heap_information_registrar;
const ::adt::MechanismRegistrar<::adt::RtlQueryProcessDebugInformationMechanism>
    g_rtl_query_process_debug_information_registrar;
}
