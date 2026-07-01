#pragma once

#include "../Core/IAntiDebugMechanism.h"

namespace adt {

// FrameworkSelfTestMechanism is not an anti-debugging technique. It is a
// harmless live-mode scaffold check used to prove that registration, polling,
// UI refresh, and result rendering are working before real mechanisms are
// added. It always returns a clean result and should stay boring by design.
// Students can compare this row with real mechanisms to separate framework
// behavior from Windows anti-debug artifacts.
class FrameworkSelfTestMechanism final : public IAntiDebugMechanism {
public:
    std::wstring_view Id() const noexcept override;
    std::wstring_view Name() const noexcept override;
    std::wstring_view Category() const noexcept override;
    std::wstring_view Description() const noexcept override;

    MechanismResult Run(const MechanismContext& context) override;
};

}  // namespace adt
