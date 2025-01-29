#include "aimbot.h"
#include <cmath>
#include <algorithm>

#define _USE_MATH_DEFINES
#include <cmath>
#include <math.h>

// Konfiguration
const float SMOOTH_FACTOR = 15.0f;
const float HEAD_OFFSET = 70.0f; // Kopfposition über vOrigin

#define MAX_PLAYERS 18
#define REFDEF_OFFSET 0x131CF0      // refdef_t = cg_t + 0x131CF0
#define CLIENTINFO_OFFSET 0x2E7A40  // clientinfo_t = cg_t + 0x2E7A40
#define CLIENTINFO_SIZE 0xED0       // Größe clientinfo_t
#define CENTITY_SIZE 0x900          // Größe centity_t


struct Angles {
    float yaw;
    float pitch;
};

static Angles CalculateAngles(const Vec3& localPos, const Vec3& targetPos) {
    Vec3 delta = targetPos - localPos;
    // Yaw (horizontal)
    float yaw = atan2f(delta.y, delta.x) * (180.0f / static_cast<float>(M_PI));
    // Pitch (vertical), Spiel könnte positiven Pitch nach unten erwarten
    float pitch = -atan2f(delta.z, sqrtf(delta.x * delta.x + delta.y * delta.y)) * (180.0f / static_cast<float>(M_PI));
    return { yaw, pitch };
}

static Angles SmoothAngles(const Angles& current, const Angles& target, float factor) {
    return {
        current.yaw + (target.yaw - current.yaw) / factor,
        current.pitch + (target.pitch - current.pitch) / factor
    };
}

void Aimbot::Run(
    HANDLE hProcess,
    uint64_t cEntityPtr,
    const refdef_t& refdef,
    const cg_t& localCG,
    const clientinfo_t* clientInfos,
    int localClientNum
) {
    static bool aimbotActive = false;
    static bool lastCapsState = false;

    bool currentCapsState = (GetKeyState(VK_CAPITAL) & 0x0001);
    if (currentCapsState != lastCapsState) {
        if (currentCapsState) {
            aimbotActive = !aimbotActive;
        }
        lastCapsState = currentCapsState;
    }

    // Aktuelle ViewAngles auslesen
    centity_t localCEntity;
    uintptr_t localCEntityAddr = cEntityPtr + (localClientNum * CENTITY_SIZE);
    ReadProcessMemory(hProcess, (LPCVOID)localCEntityAddr, &localCEntity, sizeof(centity_t), nullptr);

    // Finde bestes Ziel
    float closestAngle = FLT_MAX;
    Vec3 bestTargetPos;
    centity_t entities[MAX_PLAYERS];
    ReadProcessMemory(hProcess, (LPCVOID)cEntityPtr, &entities, CENTITY_SIZE * MAX_PLAYERS, nullptr);

    for (int i = 0; i < MAX_PLAYERS; i++) {
        const centity_t& entity = entities[i];
        if (entity.clientNum == localClientNum) continue;

        const clientinfo_t& client = clientInfos[entity.clientNum];
        if (client.health <= 0 || client.teamID == clientInfos[localClientNum].teamID) continue;

        Vec3 targetHead = entity.vOrigin;
        targetHead.z += HEAD_OFFSET;

        Angles targetAngles = CalculateAngles(refdef.viewOrigin, targetHead);
        Angles currentAngles = {
            localCEntity.vAngles.x, // Yaw
            localCEntity.vAngles.y  // Pitch
        };

        float angleDiff = sqrtf(
            powf(targetAngles.yaw - currentAngles.yaw, 2) +
            powf(targetAngles.pitch - currentAngles.pitch, 2)
        );

        if (angleDiff < closestAngle) {
            closestAngle = angleDiff;
            bestTargetPos = targetHead;
        }
    }

    // Schreibe neue Angles
    if (closestAngle != FLT_MAX) {
        Angles targetAngles = CalculateAngles(refdef.viewOrigin, bestTargetPos);
        Angles currentAngles = { localCEntity.vAngles.x, localCEntity.vAngles.y };
        Angles smoothed = SmoothAngles(currentAngles, targetAngles, SMOOTH_FACTOR);

        Vec3 newAngles = { smoothed.yaw, smoothed.pitch, 0.0f };
        WriteProcessMemory(
            hProcess,
            (LPVOID)(localCEntityAddr + offsetof(centity_t, vAngles)),
            &newAngles,
            sizeof(Vec3),
            nullptr
        );
    }



}