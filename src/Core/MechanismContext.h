#pragma once

#include <Windows.h>

namespace adt {

enum class ExecutionMode {
    Manual,
    Live
};

struct MechanismContext {
    HWND owner_window = nullptr;
    ExecutionMode mode = ExecutionMode::Manual;
};

}  // namespace adt
