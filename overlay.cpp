#include "overlay.h"

std::wstring GenerateRandomTitle() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(10000, 99999);
    return L"App_" + std::to_wstring(dist(gen));
}

void InitDirect2D(OverlayContext& ctx) {
    // Direct2D Factory
    D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &ctx.pFactory);

    // Render Target für das Fenster
    RECT rc;
    GetClientRect(ctx.hWnd, &rc);
    ctx.pFactory->CreateHwndRenderTarget(
        D2D1::RenderTargetProperties(),
        D2D1::HwndRenderTargetProperties(
            ctx.hWnd,
            D2D1::SizeU(rc.right - rc.left, rc.bottom - rc.top)
        ),
        &ctx.pRenderTarget
    );

    // Standard-Brush
    ctx.pRenderTarget->CreateSolidColorBrush(
        D2D1::ColorF(D2D1::ColorF::Red),
        &ctx.pBrush
    );

    // DirectWrite für Text
    DWriteCreateFactory(
        DWRITE_FACTORY_TYPE_SHARED,
        __uuidof(IDWriteFactory),
        reinterpret_cast<IUnknown**>(&ctx.pDWriteFactory)
    );

    ctx.pDWriteFactory->CreateTextFormat(
        L"Arial",
        nullptr,
        DWRITE_FONT_WEIGHT_NORMAL,
        DWRITE_FONT_STYLE_NORMAL,
        DWRITE_FONT_STRETCH_NORMAL,
        14.0f,
        L"",
        &ctx.pTextFormat
    );
    ctx.pTextFormat->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);

}

void CleanupDirect2D(OverlayContext& ctx) {
    if (ctx.pTextFormat) ctx.pTextFormat->Release();
    if (ctx.pDWriteFactory) ctx.pDWriteFactory->Release();
    if (ctx.pBrush) ctx.pBrush->Release();
    if (ctx.pRenderTarget) ctx.pRenderTarget->Release();
    if (ctx.pFactory) ctx.pFactory->Release();
}

OverlayContext CreateOverlay(HWND targetWindow) {
    OverlayContext ctx = {};

    // 1. Fenster erstellen
    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"D2DOverlayClass";
    RegisterClassExW(&wc);

    RECT targetRect;
    GetWindowRect(targetWindow, &targetRect);

    ctx.hWnd = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        L"D2DOverlayClass",
        GenerateRandomTitle().c_str(),
        WS_POPUP,
        targetRect.left,
        targetRect.top,
        targetRect.right - targetRect.left,
        targetRect.bottom - targetRect.top,
        nullptr,
        nullptr,
        GetModuleHandleW(nullptr),
        nullptr
    );

    SetLayeredWindowAttributes(ctx.hWnd, RGB(0, 0, 0), 0, LWA_COLORKEY);
    ShowWindow(ctx.hWnd, SW_SHOW);

    // 2. Direct2D initialisieren
    InitDirect2D(ctx);

    return ctx;
}