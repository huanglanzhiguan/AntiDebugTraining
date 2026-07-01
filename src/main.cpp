#include "App/MainWindow.h"

#include <Windows.h>

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int show_command) {
    adt::MainWindow main_window(instance);

    if (!main_window.Create(show_command)) {
        MessageBoxW(nullptr, L"Unable to create main window.", L"AntiDebugTraining", MB_ICONERROR | MB_OK);
        return 1;
    }

    return main_window.RunMessageLoop();
}

