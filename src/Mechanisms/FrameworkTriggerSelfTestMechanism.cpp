#include "FrameworkTriggerSelfTestMechanism.h"

#include "../Core/MechanismRegistry.h"

namespace adt {

std::wstring_view FrameworkTriggerSelfTestMechanism::Id() const noexcept {
    return L"framework.trigger_self_test";
}

std::wstring_view FrameworkTriggerSelfTestMechanism::Name() const noexcept {
    return L"Framework trigger self-test";
}

std::wstring_view FrameworkTriggerSelfTestMechanism::Category() const noexcept {
    return L"Framework";
}

std::wstring_view FrameworkTriggerSelfTestMechanism::Description() const noexcept {
    return L"Confirms that trigger-only mechanism selection and execution work.";
}

bool FrameworkTriggerSelfTestMechanism::SupportsLiveMode() const noexcept {
    return false;
}

MechanismResult FrameworkTriggerSelfTestMechanism::Run(const MechanismContext&) {
    return MechanismResult::Clean(L"trigger execution path completed");
}

}  // namespace adt

namespace {
const ::adt::MechanismRegistrar<::adt::FrameworkTriggerSelfTestMechanism> g_framework_trigger_self_test_registrar;
}

