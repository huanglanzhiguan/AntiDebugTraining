#include "MainWindow.h"

#include "../Core/MechanismRegistry.h"

#include <CommCtrl.h>
#include <Uxtheme.h>

#include <cstring>
#include <exception>
#include <string>

namespace {

constexpr int kClearButtonId = 1002;
constexpr int kActionBaseId = 4000;
constexpr UINT_PTR kLiveTimerId = 2001;
constexpr UINT kLiveIntervalMs = 1000;

constexpr int kOuterMargin = 14;
constexpr int kHintHeight = 28;
constexpr int kButtonHeight = 30;
constexpr int kHeaderHeight = 24;
constexpr int kRowHeight = 36;
constexpr int kStatusHeight = 24;

constexpr int kActionWidth = 92;
constexpr int kNameWidth = 230;
constexpr int kCategoryWidth = 120;
constexpr int kModeWidth = 82;
constexpr int kStatusWidth = 132;
constexpr int kLastCheckedWidth = 98;
constexpr int kColumnGap = 8;

std::wstring Copy(std::wstring_view value) {
    return std::wstring(value.data(), value.size());
}

HMENU ControlId(int id) {
    return reinterpret_cast<HMENU>(static_cast<INT_PTR>(id));
}

HFONT CreateUIFont(HWND owner, int point_size, int weight) {
    HDC dc = GetDC(owner);
    const int dpi_y = GetDeviceCaps(dc, LOGPIXELSY);
    ReleaseDC(owner, dc);

    return CreateFontW(
        -MulDiv(point_size, dpi_y, 72),
        0,
        0,
        0,
        weight,
        FALSE,
        FALSE,
        FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"Segoe UI");
}

std::wstring CurrentTimeText() {
    SYSTEMTIME now = {};
    GetLocalTime(&now);

    wchar_t buffer[16] = {};
    swprintf_s(buffer, L"%02u:%02u:%02u", now.wHour, now.wMinute, now.wSecond);
    return buffer;
}

std::wstring ExceptionText(const std::exception& error) {
    const char* what = error.what();
    return std::wstring(what, what + std::strlen(what));
}

HWND CreateStaticLabel(HWND parent, HINSTANCE instance, const wchar_t* text) {
    return CreateWindowExW(
        0,
        L"STATIC",
        text,
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE | SS_NOPREFIX,
        0,
        0,
        0,
        0,
        parent,
        nullptr,
        instance,
        nullptr);
}

}  // namespace

namespace adt {

MainWindow::MainWindow(HINSTANCE instance)
    : instance_(instance) {
}

bool MainWindow::Create(int show_command) {
    INITCOMMONCONTROLSEX controls = {};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&controls);

    const wchar_t* class_name = L"AntiDebugTrainingMainWindow";

    WNDCLASSEXW window_class = {};
    window_class.cbSize = sizeof(window_class);
    window_class.hInstance = instance_;
    window_class.lpfnWndProc = &MainWindow::WindowProc;
    window_class.lpszClassName = class_name;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);

    RegisterClassExW(&window_class);

    window_ = CreateWindowExW(
        0,
        class_name,
        L"AntiDebugTraining",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        980,
        520,
        nullptr,
        nullptr,
        instance_,
        this);

    if (window_ == nullptr) {
        return false;
    }

    ShowWindow(window_, show_command);
    UpdateWindow(window_);
    return true;
}

int MainWindow::RunMessageLoop() {
    MSG message = {};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    return static_cast<int>(message.wParam);
}

LRESULT CALLBACK MainWindow::WindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    MainWindow* self = nullptr;

    if (message == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
        self = static_cast<MainWindow*>(create->lpCreateParams);
        self->window_ = window;
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    }

    if (self != nullptr) {
        return self->HandleMessage(message, wparam, lparam);
    }

    return DefWindowProcW(window, message, wparam, lparam);
}

LRESULT MainWindow::HandleMessage(UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_CREATE:
        CreateControls();
        LoadMechanisms();
        SetTimer(window_, kLiveTimerId, kLiveIntervalMs, nullptr);
        return 0;

    case WM_SIZE:
        LayoutControls(LOWORD(lparam), HIWORD(lparam));
        InvalidateRect(window_, nullptr, TRUE);
        return 0;

    case WM_COMMAND: {
        const WORD control_id = LOWORD(wparam);
        size_t row_index = 0;

        if (control_id == kClearButtonId) {
            ClearResults();
            return 0;
        }

        if (IsActionControlId(control_id, &row_index)) {
            if (IsLiveMechanism(row_index)) {
                if (IsRowChecked(row_index)) {
                    RunMechanism(row_index, ExecutionMode::Live);
                } else {
                    mechanisms_[row_index].result = MechanismResult::NotRun();
                    mechanisms_[row_index].last_checked.clear();
                    RefreshMechanismRow(row_index);
                    SetStatusText(L"Live row disabled.");
                }
            } else {
                RunMechanism(row_index, ExecutionMode::Manual);
            }

            return 0;
        }

        break;
    }

    case WM_TIMER:
        if (wparam == kLiveTimerId) {
            RunLiveMechanisms();
            return 0;
        }
        break;

    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wparam);
        SetBkColor(dc, RGB(250, 250, 250));
        SetTextColor(dc, RGB(32, 32, 32));
        return reinterpret_cast<LRESULT>(window_brush_);
    }

    case WM_ERASEBKGND: {
        RECT client = {};
        GetClientRect(window_, &client);
        FillRect(reinterpret_cast<HDC>(wparam), &client, window_brush_);
        return 1;
    }

    case WM_DESTROY:
        KillTimer(window_, kLiveTimerId);
        if (ui_font_ != nullptr) {
            DeleteObject(ui_font_);
            ui_font_ = nullptr;
        }
        if (header_font_ != nullptr) {
            DeleteObject(header_font_);
            header_font_ = nullptr;
        }
        if (window_brush_ != nullptr) {
            DeleteObject(window_brush_);
            window_brush_ = nullptr;
        }
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }

    return DefWindowProcW(window_, message, wparam, lparam);
}

void MainWindow::CreateControls() {
    window_brush_ = CreateSolidBrush(RGB(250, 250, 250));
    ui_font_ = CreateUIFont(window_, 9, FW_NORMAL);
    header_font_ = CreateUIFont(window_, 9, FW_SEMIBOLD);

    hint_label_ = CreateStaticLabel(
        window_,
        instance_,
        L"Live rows poll while checked. Trigger rows run with their Check button.");
    ApplyUIFont(hint_label_);

    clear_button_ = CreateWindowExW(
        0,
        L"BUTTON",
        L"Clear results",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0,
        0,
        0,
        0,
        window_,
        ControlId(kClearButtonId),
        instance_,
        nullptr);
    ApplyUIFont(clear_button_);
    SetWindowTheme(clear_button_, L"Explorer", nullptr);

    CreateHeaderControls();

    status_label_ = CreateStaticLabel(window_, instance_, L"Ready.");
    ApplyUIFont(status_label_);
}

void MainWindow::CreateHeaderControls() {
    header_action_label_ = CreateStaticLabel(window_, instance_, L"Action");
    header_name_label_ = CreateStaticLabel(window_, instance_, L"Mechanism");
    header_category_label_ = CreateStaticLabel(window_, instance_, L"Category");
    header_mode_label_ = CreateStaticLabel(window_, instance_, L"Mode");
    header_status_label_ = CreateStaticLabel(window_, instance_, L"Status");
    header_details_label_ = CreateStaticLabel(window_, instance_, L"Details");
    header_last_checked_label_ = CreateStaticLabel(window_, instance_, L"Last check");

    ApplyHeaderFont(header_action_label_);
    ApplyHeaderFont(header_name_label_);
    ApplyHeaderFont(header_category_label_);
    ApplyHeaderFont(header_mode_label_);
    ApplyHeaderFont(header_status_label_);
    ApplyHeaderFont(header_details_label_);
    ApplyHeaderFont(header_last_checked_label_);
}

void MainWindow::LoadMechanisms() {
    auto registered = MechanismRegistry::Instance().CreateMechanisms();
    mechanisms_.reserve(registered.size());

    for (auto& mechanism : registered) {
        MechanismRow row;
        row.mechanism = std::move(mechanism);
        mechanisms_.push_back(std::move(row));
        CreateMechanismRow(mechanisms_.size() - 1);
        RefreshMechanismRow(mechanisms_.size() - 1);
    }

    RECT client = {};
    GetClientRect(window_, &client);
    LayoutControls(client.right - client.left, client.bottom - client.top);

    if (mechanisms_.empty()) {
        SetStatusText(L"No mechanisms registered yet.");
    } else {
        SetStatusText(std::to_wstring(mechanisms_.size()) + L" mechanism(s) registered.");
    }
}

void MainWindow::CreateMechanismRow(size_t index) {
    MechanismRow& row = mechanisms_.at(index);
    const int control_id = kActionBaseId + static_cast<int>(index);

    if (IsLiveMechanism(index)) {
        row.action_control = CreateWindowExW(
            0,
            L"BUTTON",
            L"Live",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            0,
            0,
            0,
            0,
            window_,
            ControlId(control_id),
            instance_,
            nullptr);
        SendMessageW(row.action_control, BM_SETCHECK, BST_CHECKED, 0);
    } else {
        row.action_control = CreateWindowExW(
            0,
            L"BUTTON",
            L"Check",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0,
            0,
            0,
            0,
            window_,
            ControlId(control_id),
            instance_,
            nullptr);
    }

    ApplyUIFont(row.action_control);
    SetWindowTheme(row.action_control, L"Explorer", nullptr);

    row.name_label = CreateStaticLabel(window_, instance_, L"");
    row.category_label = CreateStaticLabel(window_, instance_, L"");
    row.mode_label = CreateStaticLabel(window_, instance_, L"");
    row.status_label = CreateStaticLabel(window_, instance_, L"");
    row.detail_label = CreateStaticLabel(window_, instance_, L"");
    row.last_checked_label = CreateStaticLabel(window_, instance_, L"");

    ApplyUIFont(row.name_label);
    ApplyUIFont(row.category_label);
    ApplyUIFont(row.mode_label);
    ApplyUIFont(row.status_label);
    ApplyUIFont(row.detail_label);
    ApplyUIFont(row.last_checked_label);
}

void MainWindow::LayoutControls(int width, int height) {
    const int content_width = width - (kOuterMargin * 2);
    const int top = kOuterMargin;
    const int hint_width = content_width > 130 ? content_width - 130 : content_width;

    MoveWindow(hint_label_, kOuterMargin, top, hint_width > 20 ? hint_width : 20, kHintHeight, TRUE);
    MoveWindow(clear_button_, width - kOuterMargin - 116, top, 116, kButtonHeight, TRUE);

    const int header_y = top + kHintHeight + 12;
    LayoutHeader(header_y, content_width);

    const int first_row_y = header_y + kHeaderHeight + 4;
    for (size_t i = 0; i < mechanisms_.size(); ++i) {
        LayoutRow(i, first_row_y + static_cast<int>(i) * kRowHeight, content_width);
    }

    MoveWindow(
        status_label_,
        kOuterMargin,
        height - kOuterMargin - kStatusHeight,
        content_width,
        kStatusHeight,
        TRUE);
}

void MainWindow::LayoutHeader(int y, int width) {
    int x = kOuterMargin;
    const int details_width = width - kActionWidth - kNameWidth - kCategoryWidth - kModeWidth -
        kStatusWidth - kLastCheckedWidth - (kColumnGap * 6);

    MoveWindow(header_action_label_, x, y, kActionWidth, kHeaderHeight, TRUE);
    x += kActionWidth + kColumnGap;
    MoveWindow(header_name_label_, x, y, kNameWidth, kHeaderHeight, TRUE);
    x += kNameWidth + kColumnGap;
    MoveWindow(header_category_label_, x, y, kCategoryWidth, kHeaderHeight, TRUE);
    x += kCategoryWidth + kColumnGap;
    MoveWindow(header_mode_label_, x, y, kModeWidth, kHeaderHeight, TRUE);
    x += kModeWidth + kColumnGap;
    MoveWindow(header_status_label_, x, y, kStatusWidth, kHeaderHeight, TRUE);
    x += kStatusWidth + kColumnGap;
    MoveWindow(header_details_label_, x, y, details_width > 120 ? details_width : 120, kHeaderHeight, TRUE);
    x += (details_width > 120 ? details_width : 120) + kColumnGap;
    MoveWindow(header_last_checked_label_, x, y, kLastCheckedWidth, kHeaderHeight, TRUE);
}

void MainWindow::LayoutRow(size_t index, int y, int width) {
    MechanismRow& row = mechanisms_.at(index);
    int x = kOuterMargin;
    const int details_width = width - kActionWidth - kNameWidth - kCategoryWidth - kModeWidth -
        kStatusWidth - kLastCheckedWidth - (kColumnGap * 6);

    MoveWindow(row.action_control, x, y + 4, kActionWidth, kButtonHeight, TRUE);
    x += kActionWidth + kColumnGap;
    MoveWindow(row.name_label, x, y, kNameWidth, kRowHeight, TRUE);
    x += kNameWidth + kColumnGap;
    MoveWindow(row.category_label, x, y, kCategoryWidth, kRowHeight, TRUE);
    x += kCategoryWidth + kColumnGap;
    MoveWindow(row.mode_label, x, y, kModeWidth, kRowHeight, TRUE);
    x += kModeWidth + kColumnGap;
    MoveWindow(row.status_label, x, y, kStatusWidth, kRowHeight, TRUE);
    x += kStatusWidth + kColumnGap;
    MoveWindow(row.detail_label, x, y, details_width > 120 ? details_width : 120, kRowHeight, TRUE);
    x += (details_width > 120 ? details_width : 120) + kColumnGap;
    MoveWindow(row.last_checked_label, x, y, kLastCheckedWidth, kRowHeight, TRUE);
}

void MainWindow::RefreshMechanismRow(size_t index) {
    const MechanismRow& row = mechanisms_.at(index);

    SetWindowTextW(row.name_label, Copy(row.mechanism->Name()).c_str());
    SetWindowTextW(row.category_label, Copy(row.mechanism->Category()).c_str());
    SetWindowTextW(row.mode_label, IsLiveMechanism(index) ? L"Live" : L"Trigger");
    SetWindowTextW(row.status_label, ToDisplayText(row.result.state));
    SetWindowTextW(row.detail_label, row.result.detail.c_str());
    SetWindowTextW(row.last_checked_label, row.last_checked.c_str());
}

void MainWindow::RunLiveMechanisms() {
    if (is_running_) {
        return;
    }

    if (mechanisms_.empty()) {
        SetStatusText(L"No mechanisms registered yet.");
        return;
    }

    is_running_ = true;
    bool any_enabled = false;
    bool detected = false;
    bool any_error = false;

    for (size_t i = 0; i < mechanisms_.size(); ++i) {
        if (!IsLiveMechanism(i) || !IsRowChecked(i)) {
            continue;
        }

        any_enabled = true;
        RunMechanism(i, ExecutionMode::Live);

        if (mechanisms_[i].result.state == DetectionState::DebuggerDetected) {
            detected = true;
        } else if (mechanisms_[i].result.state == DetectionState::Error) {
            any_error = true;
        }
    }

    if (!any_enabled) {
        SetStatusText(L"No live rows enabled.");
    } else if (detected) {
        SetStatusText(L"debugger detected");
    } else if (any_error) {
        SetStatusText(L"Completed with errors.");
    } else {
        SetStatusText(L"clean");
    }

    is_running_ = false;
}

void MainWindow::RunMechanism(size_t index, ExecutionMode mode) {
    MechanismContext context;
    context.owner_window = window_;
    context.mode = mode;

    SetStatusText(L"Running: " + Copy(mechanisms_[index].mechanism->Name()));
    mechanisms_[index].result = MechanismResult::Running();
    RefreshMechanismRow(index);
    UpdateWindow(window_);

    try {
        mechanisms_[index].result = mechanisms_[index].mechanism->Run(context);
    } catch (const std::exception& error) {
        mechanisms_[index].result = MechanismResult::Error(L"exception: " + ExceptionText(error));
    } catch (...) {
        mechanisms_[index].result = MechanismResult::Error(L"unknown exception");
    }

    mechanisms_[index].last_checked = CurrentTimeText();
    RefreshMechanismRow(index);
}

void MainWindow::ClearResults() {
    for (size_t i = 0; i < mechanisms_.size(); ++i) {
        mechanisms_[i].result = MechanismResult::NotRun();
        mechanisms_[i].last_checked.clear();
        RefreshMechanismRow(i);
    }

    SetStatusText(L"Results cleared.");
}

void MainWindow::SetStatusText(const std::wstring& text) {
    SetWindowTextW(status_label_, text.c_str());
}

void MainWindow::ApplyUIFont(HWND control) {
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(ui_font_), TRUE);
}

void MainWindow::ApplyHeaderFont(HWND control) {
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(header_font_), TRUE);
}

bool MainWindow::IsLiveMechanism(size_t index) const {
    return mechanisms_.at(index).mechanism->SupportsLiveMode();
}

bool MainWindow::IsRowChecked(size_t index) const {
    return SendMessageW(mechanisms_.at(index).action_control, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

bool MainWindow::IsActionControlId(WORD control_id, size_t* index) const {
    if (control_id < kActionBaseId) {
        return false;
    }

    const size_t candidate = static_cast<size_t>(control_id - kActionBaseId);
    if (candidate >= mechanisms_.size()) {
        return false;
    }

    *index = candidate;
    return true;
}

}  // namespace adt
