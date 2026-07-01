#pragma once

#include <string>
#include <utility>

namespace adt {

enum class DetectionState {
    NotRun,
    Running,
    Clean,
    DebuggerDetected,
    NotApplicable,
    Error
};

struct MechanismResult {
    DetectionState state = DetectionState::NotRun;
    std::wstring detail;

    static MechanismResult NotRun() {
        return { DetectionState::NotRun, L"not run" };
    }

    static MechanismResult Running() {
        return { DetectionState::Running, L"running" };
    }

    static MechanismResult Clean(std::wstring detail = L"clean") {
        return { DetectionState::Clean, std::move(detail) };
    }

    static MechanismResult Detected(std::wstring detail = L"debugger detected") {
        return { DetectionState::DebuggerDetected, std::move(detail) };
    }

    static MechanismResult NotApplicable(std::wstring detail) {
        return { DetectionState::NotApplicable, std::move(detail) };
    }

    static MechanismResult Error(std::wstring detail) {
        return { DetectionState::Error, std::move(detail) };
    }
};

const wchar_t* ToDisplayText(DetectionState state) noexcept;

}  // namespace adt
