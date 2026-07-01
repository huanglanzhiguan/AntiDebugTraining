#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// FrameworkTriggerSelfTestMechanism is a harmless trigger-mode scaffold check.
// It exists to demonstrate the "manual action" path for mechanisms that should
// not run continuously. Real trigger mechanisms may create temporary local
// state, raise a controlled exception, or otherwise perform a one-shot action.
// This self-test avoids all of that and simply proves that the UI button,
// status transition, and result display work.
class FrameworkTriggerSelfTestMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;
    bool SupportsLiveMode() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
