#pragma once
#include <Windows.h>
#include <d2d1.h>
#include <dwrite.h>
#include <string>
#include <random>

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")

struct OverlayContext {
    HWND hWnd;
    ID2D1Factory* pFactory;
    ID2D1HwndRenderTarget* pRenderTarget;
    ID2D1SolidColorBrush* pBrush;
    IDWriteFactory* pDWriteFactory;
    IDWriteTextFormat* pTextFormat;
};

// Hilfsfunktionen
std::wstring GenerateRandomTitle();
void InitDirect2D(OverlayContext& ctx);
void CleanupDirect2D(OverlayContext& ctx);

// Hauptfunktion
OverlayContext CreateOverlay(HWND targetWindow);