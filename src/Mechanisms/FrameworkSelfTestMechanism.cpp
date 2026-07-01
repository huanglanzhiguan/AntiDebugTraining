#include "FrameworkSelfTestMechanism.h"

#include "../Core/MechanismRegistry.h"

namespace adt {

std::wstring_view FrameworkSelfTestMechanism::Id() const noexcept {
    return L"framework.live_self_test";
}

std::wstring_view FrameworkSelfTestMechanism::Name() const noexcept {
    return L"Framework live self-test";
}

std::wstring_view FrameworkSelfTestMechanism::Category() const noexcept {
    return L"Framework";
}

std::wstring_view FrameworkSelfTestMechanism::Description() const noexcept {
    return L"Confirms that live mechanism registration, polling, and result rendering work.";
}

MechanismResult FrameworkSelfTestMechanism::Run(const MechanismContext&) {
    return MechanismResult::Clean(L"framework execution path completed");
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::FrameworkSelfTestMechanism> g_framework_self_test_registrar;
}
