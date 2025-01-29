#include "structs.h"
#include "read.h"
#include "process_utils.h"
#include "overlay.h"  

OverlayContext gOverlayCtx;
HWND gGameWindow = nullptr;

bool InitOverlay(DWORD procID) {
    gGameWindow = FindMainWindow(procID);
    if (!gGameWindow) {
        std::cerr << "Game window not found!\n";
        return false;
    }

    gOverlayCtx = CreateOverlay(gGameWindow);
    return gOverlayCtx.hWnd != nullptr;
}

// Overlay-Update in eigener Funktion
void UpdateOverlay() {
    RECT gameRect;
    if (GetWindowRect(gGameWindow, &gameRect)) {
        MoveWindow(
            gOverlayCtx.hWnd,
            gameRect.left,
            gameRect.top,
            gameRect.right - gameRect.left,
            gameRect.bottom - gameRect.top,
            TRUE
        );
    }
}

int main() {
    DWORD procID = 0;
    uintptr_t baseAddress = 0;

    // Prozess finden
    std::cout << "Searching for process...\n";
    while (!procID) {
        procID = GetProcessIdByName(L"BlackOps3.exe");
      
    }

    // Overlay initialisieren
    if (!InitOverlay(procID)) {
        return 1;
    }

    // Basisadresse holen
    baseAddress = GetModuleBaseAddy(procID, L"blackops3.exe");
    std::cout << std::hex << "[+] baseAddress: 0x" << baseAddress << "\n";

    // Prozess-Handle öffnen
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID); //needs to be PROCESS_ALL_ACCESS
    if (!hProcess) {
        std::cerr << "OpenProcess failed: " << GetLastError() << "\n";
        CleanupDirect2D(gOverlayCtx);
        return 1;
    }

    // Hauptloop
    while (IsWindow(gGameWindow)) {  
        // Overlay position updaten
        UpdateOverlay();

        // Rendern starten
        gOverlayCtx.pRenderTarget->BeginDraw();
        gOverlayCtx.pRenderTarget->Clear(D2D1::ColorF(0, 0, 0, 0));

        // Spiel-Daten lesen & ESP zeichnen
        ReadStructs(hProcess, baseAddress, gOverlayCtx);

        // Rendern beenden
        HRESULT hr = gOverlayCtx.pRenderTarget->EndDraw();
        if (hr == D2DERR_RECREATE_TARGET) {
            CleanupDirect2D(gOverlayCtx);
            InitDirect2D(gOverlayCtx);
        }

    }

    // Aufräumen
    CleanupDirect2D(gOverlayCtx);
    CloseHandle(hProcess);
    std::cout << "Exit\n";
    return 0;
}