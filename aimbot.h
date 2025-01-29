#pragma once
#include <Windows.h>
#include "structs.h"

class Aimbot {
public:
    static void Run(
        HANDLE hProcess,
        uint64_t cEntityPtr,
        const refdef_t& refdef,
        const cg_t& localCG,
        const clientinfo_t* clientInfos,
        int localClientNum
    );
};