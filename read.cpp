#include <Windows.h>
#include <TlHelp32.h>  
#include <iostream>
#include <cstdint>
#include <winternl.h>
#include <algorithm>

#include "decrypt.h"
#include "process_utils.h"
#include "structs.h"
#include "overlay.h"
#include "aimbot.h"

#define MAX_PLAYERS 18
#define REFDEF_OFFSET 0x131CF0      // refdef_t = cg_t + 0x131CF0
#define CLIENTINFO_OFFSET 0x2E7A40  // clientinfo_t = cg_t + 0x2E7A40
#define CLIENTINFO_SIZE 0xED0       // Größe clientinfo_t
#define CENTITY_SIZE 0x900          // Größe centity_t

// Globaler Cache für nicht-ändernde Pointer
struct GamePointers {
    uint64_t cgPtr = 0;
    uint64_t cgsPtr = 0;
    uint64_t cEntityPtr = 0;
    bool initialized = false;
};

extern GamePointers gGamePtrs;

GamePointers gGamePtrs;

static const Vec3 WORLD_UP(0.0f, 0.0f, 1.0f);


void InitGamePointers(HANDLE hProcess, uintptr_t baseAddress) {
    if (gGamePtrs.initialized) return;

    // Pointer einmalig berechnen
    uint64_t encrypted_CG_Ptr = GetEncryptedPointer(hProcess, baseAddress, 0x4D17C80);
    gGamePtrs.cgPtr = pCG_t_Decryption(encrypted_CG_Ptr, false, hProcess);

    uint64_t encrypted_CGs_Ptr = GetEncryptedPointer(hProcess, baseAddress, 0x4D17B70);
    gGamePtrs.cgsPtr = pCGs_Array_Decryption(encrypted_CGs_Ptr, 0, false, hProcess);

    gGamePtrs.cEntityPtr = pCEntity(encrypted_CG_Ptr, hProcess, baseAddress, 0);

    gGamePtrs.initialized = true;
}


bool WorldToScreen(const Vec3& worldPos, const refdef_t& refdef, Vec2& outScreen)
{
    // 1) Lokale Position vom Kamerapunkt aus
    Vec3 localPos = worldPos - refdef.viewOrigin;

    Vec3 forward = refdef.viewAxis;
    forward.Normalize();

    // 3) Right und Up via Kreuzprodukt "basteln"
    Vec3 right = forward.Cross(WORLD_UP);
    right.Normalize();
    Vec3 up = right.Cross(forward);
    up.Normalize();

    // 4) Dot-Products auf die lokal transformierten Achsen
    float newX = localPos.Dot(right);
    float newY = localPos.Dot(up);
    float newZ = localPos.Dot(forward);

    // Objekt liegt hinter der Kamera?
    if (newZ < 0.1f)
        return false;

    // 5) Aus tanHalfFov.x / tanHalfFov.y einen "FOV" bauen
    float halfFovX = refdef.tanHalfFov.x; // = tan(FOVx/2)
    float halfFovY = refdef.tanHalfFov.y; // = tan(FOVy/2)

    // 6) Screen-Zentrum (z.B. 2560x1440 => 1280 / 720)
    float centerX = (float)refdef.width * 0.5f;
    float centerY = (float)refdef.height * 0.5f;

    // 7) Projection
    //    Je nach Formel kann man + oder - nutzen, 
    //    probier ggf. aus, was "richtig herum" erscheint
    float px = (newX / (halfFovX * newZ));
    float py = (newY / (halfFovY * newZ));

    outScreen.x = centerX * (1.f + px);
    outScreen.y = centerY * (1.f - py);

    return true;
}



void ESPLoop(
    OverlayContext& ctx,
    HANDLE hProcess,
    uint64_t cEntity,
    uint64_t cgPtr,
    uint64_t cgsPtr,
    const refdef_t& refdef
) {
    centity_t entities[MAX_PLAYERS];
    if (!ReadProcessMemory(hProcess, (LPCVOID)cEntity, &entities, CENTITY_SIZE * MAX_PLAYERS, nullptr)) {
        std::cerr << "Failed to read entities!\n";
        return;
    }

    clientinfo_t clientInfos[MAX_PLAYERS];
    uintptr_t clientInfoBase = cgPtr + CLIENTINFO_OFFSET;
    if (!ReadProcessMemory(hProcess, (LPCVOID)clientInfoBase, &clientInfos, CLIENTINFO_SIZE * MAX_PLAYERS, nullptr)) {
        std::cerr << "Failed to read clientinfos!\n";
        return;
    }

    // --- Korrektur: Lokales Team ermitteln über cg_t->spectatingID ---
    cg_t cg;
    if (!ReadProcessMemory(hProcess, (LPCVOID)cgPtr, &cg, sizeof(cg_t), nullptr)) {
        std::cerr << "Failed to read cg_t!\n";
        return;
    }


    // Annahme: spectatingID = 0, wenn nicht im Spectator-Modus
    int localClientNum = cg.spectatingID;
    if (localClientNum < 0 || localClientNum >= MAX_PLAYERS) {
        localClientNum = 0; // Fallback, falls ungültig
    }

    int localTeam = clientInfos[localClientNum].teamID;

    wchar_t clientNameWide[64];  // Vorher 32
    size_t convertedChars = 0;

    for (int i = 0; i < MAX_PLAYERS; i++) {
        const centity_t& entity = entities[i];
        if (entity.clientNum < 0 || entity.clientNum >= MAX_PLAYERS) continue;

        const clientinfo_t& client = clientInfos[entity.clientNum];

        // Filterung
        if (entity.clientNum == localClientNum) continue; // Lokalen Spieler überspringen
        if (entity.eType != 0 && entity.eType != 4) continue; // Nur Spieler/Bots
        if (entity.isAlive == 0 || client.health <= 0) continue;
        if (client.clientName[0] == '\0') continue;

        // Team-Prüfung
        bool isEnemy = (client.teamID != localTeam);
        if (!isEnemy) continue; // Nur Gegner zeichnen

        Vec3 adjustedOrigin = entity.vOrigin;
        adjustedOrigin.z += 25.0f;

        Vec2 screenPos;
        if (!WorldToScreen(adjustedOrigin, refdef, screenPos)) continue;

        // Zeichne rote Box und Snapline
        ctx.pBrush->SetColor(D2D1::ColorF(D2D1::ColorF::Red));

        float distance = refdef.viewOrigin.Distance(adjustedOrigin);
        float boxSize = std::clamp((1300.0f / distance) * 15.0f, 8.0f, 80.0f);
        float boxWidth = boxSize * 1.8f;
        float boxHeight = boxSize * 2.8f;

        D2D1_RECT_F box = D2D1::RectF(
            screenPos.x - boxWidth / 2,
            screenPos.y - boxHeight * 0.8f,
            screenPos.x + boxWidth / 2,
            screenPos.y + boxHeight * 0.2f
        );
        ctx.pRenderTarget->DrawRectangle(box, ctx.pBrush);

        // Name
        if (client.clientName[0]) {
            mbstowcs_s(&convertedChars, clientNameWide, client.clientName, _TRUNCATE);
            swprintf_s(clientNameWide + wcslen(clientNameWide),
                64 - wcslen(clientNameWide),
                L" [%dm]",
                (int)distance / 50); 
            const D2D1_RECT_F textRect = D2D1::RectF(
                screenPos.x - 100.0f,
                box.top - 40.0f,
                screenPos.x + 100.0f,
                box.top - 2.0f
            );
            ctx.pBrush->SetColor(D2D1::ColorF(D2D1::ColorF::WhiteSmoke)); //Lime is also good
            ctx.pRenderTarget->DrawTextW(clientNameWide, wcslen(clientNameWide), ctx.pTextFormat, textRect, ctx.pBrush);
        }

        const float MAX_DISTANCE = 3000.0f;  // Anpassen nach Spielbedarf
        float distanceFactor = std::clamp(distance / MAX_DISTANCE, 0.0f, 1.0f); //clamp begrenzt den wert von value auf den min und max wert

        // Farbinterpolation Rot -> Grün
        D2D1::ColorF lineColor(
            1.0f - distanceFactor,  // R
            10.0f,                  // G
            distanceFactor,         // B
            1.0f                    // A
        );

        // Snapline
        D2D1_POINT_2F screenCenter = { refdef.width / 2.0f, refdef.height / 2.0f };
        D2D1_POINT_2F lineEnd = D2D1::Point2F(screenPos.x, box.bottom); 
        ctx.pBrush->SetColor(lineColor);
        ctx.pRenderTarget->DrawLine(
            screenCenter,
            D2D1::Point2F(screenPos.x, box.bottom),
            ctx.pBrush,
            1.5f
        );

        // Health Bar - Hintergrund
        float healthBarWidth = 3.5f;
        float healthBarHeight = box.bottom - box.top;
        float healthBarX = box.left - healthBarWidth - 2.0f;
        float healthBarY = box.top;

        D2D1_RECT_F healthBarBg = D2D1::RectF(
            healthBarX,
            healthBarY,
            healthBarX + healthBarWidth,
            box.bottom
        );
        ctx.pBrush->SetColor(D2D1::ColorF(D2D1::ColorF::DarkGray));
        ctx.pRenderTarget->FillRectangle(healthBarBg, ctx.pBrush);

        // Health Bar - Füllstand
        float healthPercent = static_cast<float>(client.health) / 100.0f;
        healthPercent = std::clamp(healthPercent, 0.0f, 1.0f);

        float filledHeight = healthBarHeight * healthPercent;
        D2D1_RECT_F healthBar = D2D1::RectF(
            healthBarX,
            box.bottom - filledHeight,
            healthBarX + healthBarWidth,
            box.bottom
        );

        // Farbe der Health Bar bleibt immer grün
        D2D1::ColorF healthColor(D2D1::ColorF::Green);

        ctx.pBrush->SetColor(healthColor);
        ctx.pRenderTarget->FillRectangle(healthBar, ctx.pBrush);


    }
}
void ReadStructs(HANDLE hProcess, uintptr_t baseAddress, OverlayContext& ctx)
{
    
    /* // Read necessary data for Aimbot
    * 
    cg_t localCG;
    clientinfo_t clientInfos[MAX_PLAYERS];
    int localClientNum = 0;
    * 
    * 
    if (!ReadProcessMemory(hProcess, (LPCVOID)gGamePtrs.cgPtr, &localCG, sizeof(cg_t), nullptr)) {
        std::cerr << "Failed to read cg_t!\n";
        return;
    }

    // Read client infos
    uintptr_t clientInfoBase = gGamePtrs.cgPtr + CLIENTINFO_OFFSET;
    if (!ReadProcessMemory(hProcess, (LPCVOID)clientInfoBase, &clientInfos, CLIENTINFO_SIZE * MAX_PLAYERS, nullptr)) {
        std::cerr << "Failed to read clientinfos!\n";
        return;
    }

    localClientNum = 0;

    ReadProcessMemory(hProcess,
        (LPCVOID)(gGamePtrs.cgPtr + REFDEF_OFFSET),
        &refdef,
        sizeof(refdef_t),
        nullptr);
    
    // Aimbot aufrufen
    Aimbot::Run(
        hProcess,
        gGamePtrs.cEntityPtr,
        refdef,
        localCG,
        clientInfos,
        localClientNum );

    */

 

// std::cout << "CG_pointer:                 0x" << std::hex << v52 << std::endl;
// std::cout << "CG_s pointer:               0x" << std::hex << v67 << "\n";
// std::cout << "CEntity pointer:            0x" << std::hex << cEntity << "\n";


    refdef_t refdef;

    if (!gGamePtrs.initialized) {
        InitGamePointers(hProcess, baseAddress);
    }


    // Read refdef
    if (!ReadProcessMemory(hProcess,
        (LPCVOID)(gGamePtrs.cgPtr + REFDEF_OFFSET),
        &refdef,
        sizeof(refdef_t),
        nullptr))
    {
        std::cerr << "Failed to read refdef!\n";
        return;
    }



    ESPLoop(ctx, hProcess, gGamePtrs.cEntityPtr, gGamePtrs.cgPtr, gGamePtrs.cgsPtr, refdef);

}



