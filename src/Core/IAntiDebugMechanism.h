#pragma once

#include "MechanismContext.h"
#include "MechanismResult.h"

#include <string_view>

namespace adt {

class IAntiDebugMechanism {
public:
    virtual ~IAntiDebugMechanism() = default;

    virtual std::wstring_view Id() const noexcept = 0;
    virtual std::wstring_view Name() const noexcept = 0;
    virtual std::wstring_view Category() const noexcept = 0;
    virtual std::wstring_view Description() const noexcept = 0;
    virtual bool SupportsLiveMode() const noexcept { return true; }

    virtual MechanismResult Run(const MechanismContext& context) = 0;
};

}  // namespace adt
