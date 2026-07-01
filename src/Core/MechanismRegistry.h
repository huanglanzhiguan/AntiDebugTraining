#pragma once

#include "IAntiDebugMechanism.h"

#include <memory>
#include <vector>

namespace adt {

using MechanismFactory = std::unique_ptr<IAntiDebugMechanism>(*)();

class MechanismRegistry {
public:
    static MechanismRegistry& Instance();

    void RegisterFactory(MechanismFactory factory);
    std::vector<std::unique_ptr<IAntiDebugMechanism>> CreateMechanisms() const;

private:
    std::vector<MechanismFactory> factories_;
};

template <typename T>
class MechanismRegistrar {
public:
    MechanismRegistrar() {
        MechanismRegistry::Instance().RegisterFactory(&Create);
    }

private:
    static std::unique_ptr<IAntiDebugMechanism> Create() {
        return std::make_unique<T>();
    }
};

}  // namespace adt

#define ADT_REGISTER_MECHANISM(TypeName) \
    namespace { const ::adt::MechanismRegistrar<TypeName> g_##TypeName##_registrar; }

