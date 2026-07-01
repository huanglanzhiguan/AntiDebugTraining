#include "MechanismRegistry.h"

namespace adt {

const wchar_t* ToDisplayText(DetectionState state) noexcept {
    switch (state) {
    case DetectionState::NotRun:
        return L"not run";
    case DetectionState::Running:
        return L"running";
    case DetectionState::Clean:
        return L"clean";
    case DetectionState::DebuggerDetected:
        return L"debugger detected";
    case DetectionState::NotApplicable:
        return L"not applicable";
    case DetectionState::Error:
        return L"error";
    default:
        return L"unknown";
    }
}

MechanismRegistry& MechanismRegistry::Instance() {
    static MechanismRegistry registry;
    return registry;
}

void MechanismRegistry::RegisterFactory(MechanismFactory factory) {
    factories_.push_back(factory);
}

std::vector<std::unique_ptr<IAntiDebugMechanism>> MechanismRegistry::CreateMechanisms() const {
    std::vector<std::unique_ptr<IAntiDebugMechanism>> mechanisms;
    mechanisms.reserve(factories_.size());

    for (MechanismFactory factory : factories_) {
        mechanisms.push_back(factory());
    }

    return mechanisms;
}

}  // namespace adt

