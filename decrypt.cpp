#pragma once
#include "structs.h"
#include "process_utils.h"


// bei Offset 0x60. (Bei 32-Bit-Prozessen wäre es 0x30 usw.)
static const SIZE_T OFFSET_TEB_PEB = 0x60;

uint64_t __ROR8__(uint64_t value, int count) {
    return (value >> count) | (value << (64 - count));
}

uint64_t __ROL8__(uint64_t x, int count) {
    return (x << count) | (x >> (64 - count));
}

uint64_t GetSwitchCaseValue(HANDLE hProcess)
{

    // 1) Hole die MainThreadId zum Ziel-Prozess
    DWORD pid = GetProcessId(hProcess);
    DWORD mainThreadId = GetMainThreadId(pid);
    if (!mainThreadId) {
        std::cerr << "[!] Konnte keinen Main-Thread finden.\n";
        return 0;
    }

    // 2) Thread öffnen
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, mainThreadId);
    if (!hThread) {
        std::cerr << "[!] OpenThread fehlgeschlagen. Error: " << GetLastError() << "\n";
        return 0;
    }

    // 3) TEB-Adresse holen
    PVOID tebAddr = GetTebBaseAddressOfThread(hThread);
    CloseHandle(hThread); // Threadhandle können wir nun schließen
    if (!tebAddr) {
        std::cerr << "[!] Konnte TEB-Adresse nicht ermitteln.\n";
        return 0;
    }
  

    // 4) Aus dem TEB bei Offset 0x60 den PEB-Pointer lesen
    uintptr_t pebPtr = 0;
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(
        hProcess,
        (LPCVOID)((uintptr_t)tebAddr + OFFSET_TEB_PEB),
        &pebPtr,
        sizeof(pebPtr),
        &bytesRead))
    {
        std::cerr << "[!] ReadProcessMemory(TEB->PEB) fehlgeschlagen. Error: "
            << GetLastError() << "\n";
        return 0;
    }

    uint64_t switchCaseValue = __ROR8__(pebPtr, 12) & 0xF;

    return switchCaseValue;
}

uintptr_t GetEncryptedPointer(HANDLE hProcess, uintptr_t baseAddress, uintptr_t offset) {
    uintptr_t encrypted_ptr_addr = baseAddress + offset;
    uintptr_t encrypted_value = 0;

    if (!ReadProcessMemory(hProcess, (LPCVOID)encrypted_ptr_addr,
        &encrypted_value, sizeof(encrypted_value), nullptr)) {
        std::cerr << "[!] ReadProcessMemory (encrypted_ptr) fehlgeschlagen. Error: "
            << GetLastError() << "\n";
        return 0;
    }

    return encrypted_value;
}


// Funktion für dword_342155C
uintptr_t GetDword342155C(HANDLE hProcess, uintptr_t baseAddress) {
    std::cout << "[DEBUG] GetDword342155C() aufgerufen.\n";
    uintptr_t dword_addr = baseAddress + 0x342155C;  // Offset
    uint32_t value = 0;

    std::cout << "[DEBUG] dword_342155C-Address = 0x" << std::hex << dword_addr << "\n";

    if (!ReadProcessMemory(hProcess, (LPCVOID)dword_addr, &value, sizeof(value), nullptr)) {
        std::cerr << "[!] ReadProcessMemory (dword_342155C) fehlgeschlagen. Error: "
            << GetLastError() << "\n";
        return 0;
    }

    std::cout << "[DEBUG] Gelesener dword_342155C = 0x" << std::hex << value << "\n\n";
    return value;
}


// Funktion für dword_4D4B640
uintptr_t GetDword4D4B640(HANDLE hProcess, uintptr_t baseAddress) {
    std::cout << "[DEBUG] GetDword4D4B640() aufgerufen.\n";
    uintptr_t dword_addr = baseAddress + 0x4D4B640;  // Offset
    uint32_t value = 0;

    std::cout << "[DEBUG] dword_4D4B640-Address = 0x" << std::hex << dword_addr << "\n";

    if (!ReadProcessMemory(hProcess, (LPCVOID)dword_addr, &value, sizeof(value), nullptr)) {
        std::cerr << "[!] ReadProcessMemory (dword_4D4B640) fehlgeschlagen. Error: "
            << GetLastError() << "\n";
        return 0;
    }

    std::cout << "[DEBUG] Gelesener dword_4D4B640 = 0x" << std::hex << value << "\n\n";
    return value;
}

// Funktion für dword_4D4B670
uintptr_t GetDword4D4B670(HANDLE hProcess, uintptr_t baseAddress) {
    std::cout << "[DEBUG] GetDword4D4B670() aufgerufen.\n";
    uintptr_t dword_addr = baseAddress + 0x4D4B670;  // Offset
    uint32_t value = 0;

    std::cout << "[DEBUG] dword_4D4B670-Address = 0x" << std::hex << dword_addr << "\n";

    if (!ReadProcessMemory(hProcess, (LPCVOID)dword_addr, &value, sizeof(value), nullptr)) {
        std::cerr << "[!] ReadProcessMemory (dword_4D4B670) fehlgeschlagen. Error: "
            << GetLastError() << "\n";
        return 0;
    }

    std::cout << "[DEBUG] Gelesener dword_4D4B670 = 0x" << std::hex << value << "\n\n";
    return value;
}

// Funktion für off_168EDE28
uintptr_t GetOff168EDE28(HANDLE hProcess, uintptr_t baseAddress) {
    std::cout << "[DEBUG] GetOff168EDE28() aufgerufen.\n";
    uintptr_t off_addr = baseAddress + 0x168EDE28;  // Offset
    uint32_t value = 0;

    std::cout << "[DEBUG] off_168EDE28-Address = 0x" << std::hex << off_addr << "\n";

    if (!ReadProcessMemory(hProcess, (LPCVOID)off_addr, &value, sizeof(value), nullptr)) {
        std::cerr << "[!] ReadProcessMemory (off_168EDE28) fehlgeschlagen. Error: "
            << GetLastError() << "\n";
        return 0;
    }

    std::cout << "[DEBUG] Gelesener off_168EDE28 = 0x" << std::hex << value << "\n\n";
    return value;
}

// Funktion für unk_4D40E20
uintptr_t GetUnk4D40E20(HANDLE hProcess, uintptr_t baseAddress) {
    std::cout << "[DEBUG] GetUnk4D40E20() aufgerufen.\n";
    uintptr_t unk_addr = baseAddress + 0x4D40E20;  // Offset
    uint32_t value = 0;

    std::cout << "[DEBUG] unk_4D40E20-Address = 0x" << std::hex << unk_addr << "\n";

    if (!ReadProcessMemory(hProcess, (LPCVOID)unk_addr, &value, sizeof(value), nullptr)) {
        std::cerr << "[!] ReadProcessMemory (unk_4D40E20) fehlgeschlagen. Error: "
            << GetLastError() << "\n";
        return 0;
    }

    std::cout << "[DEBUG] Gelesener unk_4D40E20 = 0x" << std::hex << value << "\n\n";
    return value;
}

//get the global variable for LABEL_316 calculation
uintptr_t GetDword53A2720(HANDLE hProcess, uintptr_t baseAddress) {
    std::cout << "[DEBUG] GetDword53A2720() aufgerufen.\n";
    uintptr_t dword_addr = baseAddress + 0x53A2720;  // Offset
    uint32_t value = 0;

    std::cout << "[DEBUG] dword_53A2720-Address = 0x"
        << std::hex << dword_addr << "\n";

    if (!ReadProcessMemory(hProcess, (LPCVOID)dword_addr, &value, sizeof(value), nullptr)) {
        std::cerr << "[!] ReadProcessMemory (dword_53A2720) fehlgeschlagen. Error: "
            << GetLastError() << "\n";
        return 0;
    }

    std::cout << "[DEBUG] Gelesener dword_53A2720 = 0x"
        << std::hex << value << "\n\n";
    return value;
}


uint64_t pCGs_Array_Decryption(uint64_t encrypted_CGs_array_pointer, int a1, bool retaddrIsBig, HANDLE hProcess)
{
    __int64 clientnum; // r14
    unsigned int v2; // edx
    unsigned int v3; // edx
    int v4; // ecx
    unsigned int v5; // eax
    unsigned int v6; // edx
    int v7; // ecx
    unsigned int v8; // eax
    unsigned int v9; // edx
    int v10; // ecx
    unsigned int v11; // edx
    int v12; // ecx
    unsigned int v13; // edx
    int v14; // ecx
    __int64 v15; // rax
    unsigned int v16; // edx
    int v17; // ecx
    unsigned int v18; // eax
    unsigned int v19; // edx
    int v20; // ecx
    unsigned int v21; // edx
    int v22; // ecx
    __int64 v23; // rax
    unsigned int v24; // eax
    unsigned int v25; // edx
    int v26; // ecx
    unsigned int v27; // eax
    unsigned int v28; // edx
    int v29; // ecx
    unsigned int v30; // eax
    unsigned int v31; // edx
    int v32; // ecx
    __int64 v33; // rax
    unsigned int v34; // edx
    int v35; // ecx
    unsigned int v36; // edx
    int v37; // ecx
    unsigned int v38; // eax
    __int64 v39; // rax
    unsigned int v40; // edx
    int v41; // ecx
    unsigned int v42; // eax
    int v43; // edx
    int v44; // ecx
    __int64 v45; // rax
    unsigned int v46; // edx
    int v47; // ecx
    unsigned int v48; // eax
    __int64 v49; // rax
    __int64 v50; // rax
    __int64 cgsArray; // rsi
    __int64 v52; // rdx
    __int64 v53; // rcx
    __int64 v54; // r8
    __int64 v55; // r9
    const char** v56; // rbx
    __int64 v57; // rdi
    const char* v58; // rcx
    __int64 v59; // rax
    unsigned int v60; // eax
    __int64 v61; // rax
    __int64 v62; // r8
    const char* v64; // [rsp+20h] [rbp-E0h] BYREF
    BYTE v65[600]; // [rsp+28h] [rbp-D8h] BYREF
    __int64 v67; // [rsp+2B0h] [rbp+1B0h]
    __int64 v68; // [rsp+2B0h] [rbp+1B0h]
    __int64 v69; // [rsp+2B0h] [rbp+1B0h]
    __int64 v70; // [rsp+2B8h] [rbp+1B8h]
    __int64 v71; // [rsp+2B8h] [rbp+1B8h]
    __int64 v72; // [rsp+2B8h] [rbp+1B8h]


    v67 = encrypted_CGs_array_pointer;
    clientnum = a1;
    if (encrypted_CGs_array_pointer)
    {
        //v2 = __ROR8__(NtCurrentTeb()->ProcessEnvironmentBlock, 12) & 0xF;
        v2 = GetSwitchCaseValue(hProcess);
        v70 = v2;
        switch (v2)
        {
        case 0u:
            v3 = -1392894555;
            v4 = -2072838437;
            if (false)
            {
                v3 = -415335916;
            }
            while (v3 <= 0x43A2BAE7)
            {
                if (v3 == 1134738151)
                {
                    v4 = 1450025263;
                    v70 = (unsigned int)(1034819187 * v67 + 1563181419);
                    v67 = __ROL8__(v67, 32);
                }
                else
                {
                    if (v3 != 807954155)
                    {
                        if (v3 != 898607511)
                        {
                            if (v3 == 1038933360)
                            {
                                v70 = (unsigned int)(387286849 * v67 + 1147006403);
                                v4 = 207214972;
                                v67 = __ROL8__(__ROL8__(v67, 32) ^ v70, 32);
                            }
                            goto LABEL_24;
                        }
                        v4 = 94883708;
                        v5 = -676570275 * v70 + 1036618278;
                        goto LABEL_23;
                    }
                    v67 = __ROL8__(v67, 32) ^ v70;
                    v4 = 230996891;
                }
            LABEL_24:
                v3 ^= v4;
                if (v3 == 833946636)
                    goto LABEL_357;
            }
            if (v3 != 1199023563)
            {
                if (v3 == -1392894555)
                {
                    v70 = (unsigned int)v67;
                    v4 = -1720339406;
                }
                goto LABEL_24;
            }
            v4 = -1770465551;
            v5 = 663741583 * v70 + 55829906;
        LABEL_23:
            v70 = v5;
            goto LABEL_24;
        case 1u:
            v6 = -982893414;
            v7 = 70402853;
            if (false)
            {
                v6 = -1773451429;
            }
            while (v6 <= 0xFF088EE)
            {
                if (v6 != 267421934)
                {
                    if (v6 != 140150130)
                    {
                        switch (v6)
                        {
                        case 0x9F03B24u:
                            v67 ^= v70;
                            v7 = 59633884;
                            break;
                        case 0xA7DCBF8u:
                            v7 = -1116335929;
                            v67 = __ROR8__(v67, 32);
                            break;
                        case 0xBB0D09Du:
                            v7 = 71325811;
                            v67 = __ROR8__(v67, 32);
                            break;
                        }
                        goto LABEL_51;
                    }
                    v7 = -268692464;
                    v8 = 160679549 * v70 + 2115142831;
                    goto LABEL_50;
                }
                v68 = v67 ^ v70;
                v7 = 100709322;
                v70 = (unsigned int)(27555349 * v68 + 617046113);
                v67 = __ROR8__(v68, 32);
            LABEL_51:
                v6 ^= v7;
                if (v6 == -1223959745)
                    goto LABEL_357;
            }
            if (v6 != 1403512119)
            {
                if (v6 == -982893414)
                {
                    v70 = (unsigned int)v67;
                    v7 = -1764894291;
                }
                else if (v6 == -106960958)
                {
                    v7 = 986483512;
                    v70 = (unsigned int)(-1516411916 * v67 + 98843441);
                    v67 = __ROL8__(v67, 32);
                }
                goto LABEL_51;
            }
            v7 = 1477916074;
            v8 = 19767112 * v70 + 691895846;
        LABEL_50:
            v70 = v8;
            goto LABEL_51;
        case 2u:
            v9 = 38175326;
            v10 = 180679443;
            if (retaddrIsBig) {
                v9 = 302076;
            }
            do
            {
                if (v9 > 0x705F64D1)
                {
                    switch (v9)
                    {
                    case 0x71F20203u:
                        v67 ^= v70;
                        v10 = 62183473;
                        break;
                    case 0x7246DA32u:
                        v10 = 35241699;
                        v70 = (unsigned int)(1780415763 * v67 + 1248471934);
                        break;
                    case 0x75974734u:
                        v10 = 73745719;
                        v70 = (unsigned int)(-144385519 * v70 + 950287153);
                        v67 = __ROL8__(v67, 32);
                        break;
                    }
                }
                else
                {
                    switch (v9)
                    {
                    case 0x705F64D1u:
                        v67 = __ROL8__(v67, 32) ^ v70;
                        v10 = 1311170879;
                        break;
                    case 0x246825Eu:
                        v70 = (unsigned int)v67;
                        v10 = 2010236266;
                        break;
                    case 0x22BD2B3Eu:
                        v10 = 2054209928;
                        v70 = (unsigned int)(1983195443 * v67 + 1257911707);
                        break;
                    case 0x3E7985EEu:
                        v10 = -1161543778;
                        v67 = __ROR8__(v67, 32);
                        break;
                    case 0x3F4E3698u:
                        v10 = 64569805;
                        v70 = (unsigned int)(544989931 * v70 - 281022520);
                        v67 = __ROR8__(v67, 32);
                        break;
                    }
                }
                v9 ^= v10;
            } while (v9 != -2067940752);
            goto LABEL_357;
        case 3u:
            v11 = 2040458296;
            v12 = 664103645;
            if (retaddrIsBig) {
                v11 = 256952872;
            }
            do
            {
                if (v11 > 0x799EEC38)
                {
                    switch (v11)
                    {
                    case 0x9A4FA23E:
                        v12 = -607423327;
                        v70 = (unsigned int)(-1113230910 * v70 + 51791386);
                        break;
                    case 0xB0EF7107:
                        v69 = v67 ^ v70;
                        v12 = -1738212032;
                        v70 = (unsigned int)(635627692 * v69 + 985440974);
                        v67 = __ROR8__(v69, 32);
                        break;
                    case 0xBA3951A4:
                        v12 = -1273861656;
                        v67 = __ROL8__(v67, 32);
                        break;
                    }
                }
                else
                {
                    switch (v11)
                    {
                    case 0x799EEC38u:
                        v70 = (unsigned int)v67;
                        v12 = 153273253;
                        break;
                    case 0x1CF86F62u:
                        v12 = 182076501;
                        v70 = (unsigned int)(1077185094 * v67 - 1952418324);
                        v67 = __ROL8__(v67, 32);
                        break;
                    case 0x288B8C47u:
                        v67 ^= v70;
                        v12 = -1833771549;
                        break;
                    case 0x70BC2F9Du:
                        v12 = -1068278118;
                        v70 = (unsigned int)(1308150520 * v70 + 1249783902);
                        v67 = __ROL8__(v67, 32);
                        break;
                    }
                }
                v11 ^= v12;
            } while (v11 != 237713484);
            goto LABEL_357;
        case 4u:
            v13 = -238499147;
            v14 = 175734999;
            do
            {
                if (v13 > 0xBCEEEB72)
                {
                    switch (v13)
                    {
                    case 0xEE62712D:
                        v15 = __ROR8__(v67, 32);
                        v67 = v15 ^ v70;
                        v70 = (unsigned int)v15 ^ (unsigned int)v70;
                        v14 = 1384946271;
                        break;
                    case 0xF1C8CAB5:
                        v14 = 531282840;
                        v70 = (unsigned int)(-365377227 * v67 + 120703366);
                        break;
                    case 0xF33636A1:
                        v14 = -817180195;
                        v67 = __ROL8__(v67, 32);
                        break;
                    }
                }
                else
                {
                    switch (v13)
                    {
                    case 0xBCEEEB72:
                        v14 = -1757657159;
                        v70 = (unsigned int)(-423799622 * v70 - 861153683);
                        v67 = __ROR8__(v67, 32);
                        break;
                    case 0x2BD2ACCBu:
                        v67 ^= v70;
                        v14 = -656106902;
                        break;
                    case 0x41D63A33u:
                        v14 = 62793901;
                        v70 = (unsigned int)(1656960653 * v70 - 19719138);
                        v67 = __ROR8__(v67, 32);
                        break;
                    case 0xB49460B4:
                        v14 = -567964219;
                        v70 = (unsigned int)(311747646 * v67 - 1762563938);
                        break;
                    }
                }
                v13 ^= v14;
            } while (v13 != 1014818684);
            goto LABEL_357;
        case 5u:
            v16 = -1131517967;
            v17 = 468085902;
            if (retaddrIsBig) {
                v16 = -1189720122;
            }
            while (v16 <= 0xA7113BF9)
            {
                if (v16 == -1492042759)
                {
                    v17 = 50406953;
                    v67 = __ROR8__(v67, 32);
                }
                else
                {
                    if (v16 != 206665781)
                    {
                        if (v16 != 379028038)
                        {
                            if (v16 == 983170147)
                            {
                                v17 = -241073116;
                                v67 = __ROR8__(v67, 32);
                            }
                            else if (v16 == -1542447664)
                            {
                                v67 ^= v70;
                                v17 = -1635130957;
                            }
                            goto LABEL_131;
                        }
                        v17 = -1235487625;
                        v18 = -142666249 * v70 - 1718895763;
                        goto LABEL_130;
                    }
                    v17 = 87527895;
                    v70 = (unsigned int)(45466106 * v67 - 531631530);
                    v67 = __ROR8__(v67, 32);
                }
            LABEL_131:
                v16 ^= v17;
                if (v16 == -885491641)
                    goto LABEL_357;
            }
            if (v16 == -1449927552)
            {
                v67 ^= v70;
                v17 = 243459961;
                v18 = 211671191 * v67 - 718833409;
            }
            else
            {
                if (v16 != -1131517967)
                {
                    if (v16 == -910113344)
                    {
                        v17 = 1616058688;
                        v67 = __ROL8__(v67, 32);
                    }
                    goto LABEL_131;
                }
                v17 = 1968087601;
                v18 = 145018791 * v67 + 1966179950;
            }
        LABEL_130:
            v70 = v18;
            goto LABEL_131;
        case 6u:
            v19 = 317103759;
            v20 = -722672851;
            while (1)
            {
                if (v19 > 0x83D1D751)
                {
                    if (v19 != -1346233541)
                    {
                        if (v19 == -1015299922)
                        {
                            v20 = -1167662150;
                            v70 = (unsigned int)(-1377457499 * v70 - 22486442);
                        }
                        else if (v19 == -698589093)
                        {
                            v20 = 2040429408;
                            v70 = (unsigned int)(-2049916788 * v67 + 1570656439);
                        }
                        goto LABEL_152;
                    }
                    v20 = 739495018;
                }
                else if (v19 == -2083399855)
                {
                    v67 ^= v70;
                    v20 = 449594848;
                }
                else
                {
                    if (v19 != 167197375)
                    {
                        switch (v19)
                        {
                        case 0x12E69E8Fu:
                            v70 = (unsigned int)v67;
                            v20 = -778215903;
                            break;
                        case 0x2124D16Cu:
                            v20 = 248682141;
                            v70 = (unsigned int)(-508833115 * v70 - 797025694);
                            break;
                        case 0x791D2314u:
                            v67 = __ROR8__(v67, 32) ^ v70;
                            v20 = -1354677425;
                            break;
                        }
                        goto LABEL_152;
                    }
                    v20 = 50831817;
                    v70 = (unsigned int)(-1851342424 * v67 - 386420662);
                }
                v67 = __ROR8__(v67, 32);
            LABEL_152:
                v19 ^= v20;
                if (v19 == -1726115151)
                    goto LABEL_357;
            }
        case 7u:
            v21 = -1189324163;
            v22 = 1922285335;
            while (1)
            {
                if (v21 > 0x4A3DDFA3)
                {
                    if (v21 == -1189324163)
                    {
                        v22 = -215906850;
                        v24 = 2068298485 * v67 - 1181163500;
                        goto LABEL_168;
                    }
                    if (v21 == -560144119)
                    {
                        v22 = 1139976219;
                        v23 = __ROR8__(v67 ^ v70, 32);
                        goto LABEL_169;
                    }
                }
                else
                {
                    switch (v21)
                    {
                    case 0x4A3DDFA3u:
                        v67 ^= v70;
                        v22 = 2064955692;
                        break;
                    case 0x499984u:
                        v22 = -1751134141;
                        v24 = -804109380 * v67 - 1898451881;
                    LABEL_168:
                        v70 = v24;
                        v23 = __ROL8__(v67, 32);
                        goto LABEL_169;
                    case 0x88BF81Au:
                        v22 = 1804580222;
                        v70 = (unsigned int)(-1882106321 * v67 + 892676256);
                        v23 = __ROR8__(v67, 32);
                        goto LABEL_169;
                    case 0x3129668Fu:
                        v22 = -273315962;
                        v70 = (unsigned int)(464710969 * v67 + 168833856);
                        v23 = __ROR8__(v67, 32);
                    LABEL_169:
                        v67 = v23;
                        break;
                    }
                }
                v21 ^= v22;
                if (v21 == -1653716718)
                    goto LABEL_357;
            }
        case 8u:
            v25 = -2081957752;
            v26 = -224579502;
            if (false)
            {
                v25 = 1373173950;
            }
            while (v25 <= 0x83E7D888)
            {
                switch (v25)
                {
                case 0x83E7D888:
                    v26 = -975618847;
                    v70 = (unsigned int)(-1465571338 * v67 + 447044909);
                    v67 = __ROR8__(v67, 32);
                    break;
                case 0x2846A27Au:
                    v67 ^= v70;
                    v26 = -181290966;
                    break;
                case 0x40D09EFCu:
                    v26 = 1754676358;
                    v67 = __ROR8__(v67, 32);
                    break;
                case 0x463EE469u:
                    v67 ^= v70;
                    v26 = 116292245;
                    v27 = 6150000 * v67 - 67834788;
                LABEL_194:
                    v70 = v27;
                    break;
                }
            LABEL_195:
                v25 ^= v26;
                if (v25 == 143215331)
                    goto LABEL_357;
            }
            if (v25 != -1898146155)
            {
                if (v25 == -579397040)
                {
                    v26 = -704753485;
                    v67 = __ROR8__(v67, 32);
                }
                else if (v25 == -308439394)
                {
                    v26 = 13018054;
                    v70 = (unsigned int)(1075648295 * v67 + 197880179);
                    v67 = __ROR8__(v67, 32);
                }
                goto LABEL_195;
            }
            v26 = 248328265;
            v27 = 39737565 * v70 + 226975920;
            goto LABEL_194;
        case 9u:
            v28 = 1794488519;
            v29 = 1641926309;
            if (false)
            {
                v28 = 1688545767;
            }
            while (v28 <= 0x93D36E79)
            {
                if (v28 == -1814860167)
                {
                    v29 = -146588986;
                    v67 = __ROL8__(v67, 32);
                }
                else
                {
                    if (v28 != 830031947)
                    {
                        if (v28 != 1794488519)
                        {
                            if (v28 == 1815894317)
                            {
                                v29 = -281449005;
                                v67 = __ROL8__(v67, 32);
                            }
                            else if (v28 == -2096810754)
                            {
                                v67 ^= v70;
                                v70 = (unsigned int)v67;
                                v29 = 347829849;
                            }
                            goto LABEL_222;
                        }
                        v29 = 113893866;
                        v30 = 161289646 * v67 - 2114660705;
                        goto LABEL_221;
                    }
                    v29 = 126255278;
                    v70 = (unsigned int)(-1656594994 * v70 - 253461220);
                    v67 = __ROL8__(v67, 32);
                }
            LABEL_222:
                v28 ^= v29;
                if (v28 == 1687180479)
                    goto LABEL_357;
            }
            if (v28 != -1749138777)
            {
                if (v28 == -1601128409)
                {
                    v29 = 143595250;
                    v70 = (unsigned int)(-2027543155 * v67 - 197312098);
                    v67 = __ROR8__(v67, 32);
                }
                else if (v28 == -1057388980)
                {
                    v67 = __ROR8__(v67, 32) ^ v70;
                    v29 = 1395320885;
                }
                goto LABEL_222;
            }
            v29 = 1464321259;
            v30 = -26686589 * v70 + 1205788074;
        LABEL_221:
            v70 = v30;
            goto LABEL_222;
        case 0xAu:
            v31 = 234591737;
            v32 = 1324830669;
            if (retaddrIsBig) {
                v31 = 221876018;
            }
            while (v31 <= 0x5E2DCADC)
            {
                switch (v31)
                {
                case 0x5E2DCADCu:
                    v32 = -1577100311;
                    v33 = __ROL8__(v67, 32);
                    goto LABEL_244;
                case 0x2795686u:
                    v32 = 1549048922;
                    v70 = (unsigned int)(1934797282 * v70 + 88888424);
                    break;
                case 0xDFB95F9u:
                    v70 = (unsigned int)v67;
                    v32 = 260227967;
                    break;
                case 0x4799D44Cu:
                    v70 = (unsigned int)(410363884 * v70 - 348264109);
                    v67 = __ROR8__(v67, 32) ^ v70;
                    v32 = 256938473;
                    break;
                case 0x48C945A5u:
                    v32 = 30892795;
                    goto LABEL_243;
                }
            LABEL_245:
                v31 ^= v32;
                if (v31 == 1226712926)
                    goto LABEL_357;
            }
            if (v31 != 1633322409)
            {
                if (v31 == -1623433855)
                {
                    v32 = -1392575814;
                    v70 = (unsigned int)(-2023851788 * v70 + 180874326);
                }
                else if (v31 == -2977483)
                {
                    v67 ^= v70;
                    v70 = (unsigned int)v67;
                    v32 = -1203026567;
                }
                goto LABEL_245;
            }
            v32 = 27254445;
            v70 = (unsigned int)(-1668034232 * v70 - 314411471);
        LABEL_243:
            v33 = __ROR8__(v67, 32);
        LABEL_244:
            v67 = v33;
            goto LABEL_245;
        case 0xBu:
            v34 = 1177305226;
            v35 = -1817307402;
            if (false)
            {
                v34 = 1181993605;
            }
            do
            {
                if (v34 > 0x6C8F27A5)
                {
                    switch (v34)
                    {
                    case 0x7D5C6A82u:
                        v67 ^= v70;
                        v35 = 837357795;
                        break;
                    case 0x7F3BD545u:
                        v35 = 981986226;
                        v70 = (unsigned int)(846488127 * v70 + 339928736);
                        break;
                    case 0xC10CE535:
                        v67 ^= v70;
                        v35 = -1383873904;
                        break;
                    }
                }
                else
                {
                    switch (v34)
                    {
                    case 0x6C8F27A5u:
                        v35 = 299060519;
                        v70 = (unsigned int)(-1183024600 * v67 + 1474800213);
                        v67 = __ROR8__(v67, 32);
                        break;
                    case 0x185E8398u:
                        v35 = 108551938;
                        v70 = (unsigned int)(1370403805 * v67 - 1611197555);
                        v67 = __ROR8__(v67, 32);
                        break;
                    case 0x462C408Au:
                        v35 = -2027903553;
                        v70 = (unsigned int)(1903546760 * v67 - 1082383843);
                        v67 = __ROR8__(v67, 32);
                        break;
                    case 0x4CB57A61u:
                        v35 = -27715856;
                        v67 = __ROL8__(v67, 32);
                        break;
                    }
                }
                v34 ^= v35;
            } while (v34 != -1293128559);
            goto LABEL_357;
        case 0xCu:
            v36 = -1706496136;
            v37 = -322626256;
            if (false)
            {
                v36 = 1105517819;
            }
            while (v36 <= 0x9A48EF78)
            {
                switch (v36)
                {
                case 0x9A48EF78:
                    v70 = (unsigned int)v67;
                    v37 = 1080422630;
                    break;
                case 0x6B961D1Au:
                    v67 ^= v70;
                    v37 = 257667138;
                    goto LABEL_292;
                case 0x8C11B986:
                    v37 = 1584827990;
                    v70 = (unsigned int)(-281633437 * v70 - 2012180815);
                    break;
                case 0x96E869EC:
                    v37 = -545934733;
                    v38 = 204794897 * v67 + 1220796506;
                    goto LABEL_291;
                }
            LABEL_293:
                v36 ^= v37;
                if (v36 == 1691200856)
                    goto LABEL_357;
            }
            if (v36 != -1146688061)
            {
                if (v36 == -634576994)
                {
                    v71 = (unsigned int)(311044 * v70 + 1864979708);
                    v39 = __ROR8__(v67, 32);
                    v67 = v39 ^ v71;
                    v70 = (unsigned int)v39 ^ (unsigned int)v71;
                    v37 = 1636561501;
                }
                goto LABEL_293;
            }
            v37 = -802098983;
            v38 = 73889857 * v70 - 2038207447;
        LABEL_291:
            v70 = v38;
        LABEL_292:
            v67 = __ROR8__(v67, 32);
            goto LABEL_293;
        case 0xDu:
            v40 = -378278825;
            v41 = 130593729;
            if (false)
            {
                v40 = 990016688;
            }
            while (1)
            {
                if (v40 > 0xAF498A4A)
                {
                    switch (v40)
                    {
                    case 0xB18E8B43:
                        v41 = -79336836;
                        v42 = 187452221 * v70 + 1786168996;
                        goto LABEL_317;
                    case 0xBA9C20C1:
                        v67 ^= v70;
                        v70 = (unsigned int)v67;
                        v41 = 185772930;
                        break;
                    case 0xE973EC57:
                        v41 = -638493862;
                        v42 = 26474678 * v67 - 986723137;
                    LABEL_317:
                        v70 = v42;
                        break;
                    }
                }
                else if (v40 == -1354134966)
                {
                    v41 = -1389522275;
                    v70 = (unsigned int)(109776997 * v70 - 1088521501);
                    v67 = __ROL8__(v67, 32);
                }
                else
                {
                    if (v40 != 813872909)
                    {
                        if (v40 != 904860810)
                        {
                            if (v40 == 1254875455)
                            {
                                v41 = -628240245;
                                v67 = __ROR8__(__ROR8__(v67, 32) ^ v70, 32);
                            }
                            goto LABEL_318;
                        }
                        v41 = 138268322;
                        v42 = 912077661 * v67 - 484791423;
                        goto LABEL_317;
                    }
                    v41 = -1977706548;
                    v67 = __ROL8__(v67, 32);
                }
            LABEL_318:
                v40 ^= v41;
                if (v40 == -1874447948)
                    goto LABEL_357;
            }
        case 0xEu:
            v43 = 187485556;
            v44 = -2125572981;
            if (false)
            {
                v43 = -686920318;
            }
            do
            {
                switch (v43)
                {
                case 187485556:
                    v72 = (unsigned int)(93888103 * v67 - 270845160);
                    v45 = __ROR8__(v67, 32);
                    v67 = v45 ^ v72;
                    v44 = 85908649;
                    v70 = -940049024 * ((unsigned int)v45 ^ (unsigned int)v72) - 515799163;
                    break;
                case 238162397:
                    v44 = 253239557;
                    v67 = __ROR8__(__ROR8__(v67, 32) ^ v70, 32);
                    break;
                case 1171638463:
                    v44 = -297907137;
                    v70 = (unsigned int)(1692672854 * v67 + 54786342);
                    v67 = __ROR8__(v67, 32);
                    break;
                case 1567800138:
                    v44 = -130632963;
                    v70 = (unsigned int)(-698485160 * v67 + 1143006403);
                    v67 = __ROL8__(v67, 32);
                    break;
                }
                v43 ^= v44;
            } while (v43 != 19542232);
            goto LABEL_357;
        default:
            v46 = 131259045;
            v47 = -529990837;
            break;
        }
        do
        {
            if (v46 > 0x4025D753)
            {
                switch (v46)
                {
                case 0xBB33D98B:
                    v47 = 93026620;
                    v48 = -669199025 * v67 + 830086604;
                LABEL_353:
                    v70 = v48;
                LABEL_354:
                    v49 = __ROR8__(v67, 32);
                    goto LABEL_355;
                case 0xDE979BEE:
                    v50 = __ROL8__(v67, 32);
                    v67 = v50 ^ v70;
                    v47 = -573406875;
                    v70 = 1533317850 * ((unsigned int)v50 ^ (unsigned int)v70) - 2102562793;
                    break;
                case 0xDF9B8726:
                    v47 = -1233446954;
                    v49 = __ROL8__(v67, 32);
                LABEL_355:
                    v67 = v49;
                    break;
                }
            }
            else
            {
                switch (v46)
                {
                case 0x4025D753u:
                    v67 ^= v70;
                    v47 = -1614917515;
                    break;
                case 0x3451A8Bu:
                    v47 = 1130417624;
                    goto LABEL_354;
                case 0x7D2DAA5u:
                    v47 = -649772725;
                    v70 = (unsigned int)(79505209 * v67 + 1848601594);
                    break;
                case 0xC9C6622u:
                    v47 = -1331483316;
                    v48 = 96370430 * v70 - 1564738748;
                    goto LABEL_353;
                }
            }
            v46 ^= v47;
        } while (v46 != 1776324848);
    }
LABEL_357:
    cgsArray = v67 + 125248 * clientnum;

    return cgsArray;
}



uint64_t pCG_t_Decryption(uint64_t encrypted_value, bool retaddrIsBig, HANDLE hProcess)
{
    int Int; // eax
    __int64 v1; // r9
    unsigned int v2; // edx
    int v3; // ecx
    unsigned int v4; // edx
    int v5; // ecx
    __int64 v6; // rax
    __int64 v7; // rax
    int v8; // edx
    int v9; // ecx
    unsigned int v10; // edx
    int v11; // ecx
    __int64 v12; // rax
    unsigned int v13; // eax
    unsigned int v14; // edx
    int v15; // ecx
    int v16; // edx
    int v17; // ecx
    __int64 v18; // rax
    unsigned int v19; // eax
    unsigned int v20; // edx
    int v21; // ecx
    unsigned int v22; // edx
    int v23; // ecx
    unsigned int v24; // eax
    unsigned int v25; // edx
    int v26; // ecx
    __int64 v27; // rax
    int v28; // edx
    int v29; // ecx
    unsigned int v30; // edx
    int v31; // ecx
    unsigned int v32; // edx
    int v33; // ecx
    __int64 v34; // rax
    unsigned int v35; // eax
    unsigned int v36; // edx
    int v37; // ecx
    unsigned int v38; // edx
    int v39; // ecx
    unsigned int v40; // eax
    __int64 v41; // rax
    unsigned int v42; // edx
    int v43; // ecx
    unsigned int v44; // eax
    unsigned int v45; // edx
    int v46; // ecx
    unsigned int v47; // eax
    __int64 v48; // rbx
    __int64 v49; // rdi
    __int64 result; // rax
    __int64 v52; // [rsp+38h] [rbp+18h]
    __int64 v53; // [rsp+40h] [rbp+20h]
    __int64 v54; // [rsp+40h] [rbp+20h]
    __int64 v55; // [rsp+40h] [rbp+20h]
    __int64 v56; // [rsp+40h] [rbp+20h]

    v52 = encrypted_value;
    if (encrypted_value)
    {
        v53 = GetSwitchCaseValue(hProcess);

        switch (v53)
        {
        case 0LL:
            v2 = -182854066;
            v3 = -478971047;
            if (retaddrIsBig) {
                v2 = -761270997; //legit wert
            }
            do
            {
                if (v2 > 0x8DEB238F)
                {
                    switch (v2)
                    {
                    case 0xF3B20C43:
                        v53 = (unsigned int)v52;
                        v3 = 166269469;
                        break;
                    case 0xF519DE4E:
                        v3 = -2020477958;
                        v53 = (unsigned int)(1584075655 * v52 + 586718870);
                        v52 = __ROR8__(v52, 32);
                        break;
                    case 0xFA5B1E5E:
                        v3 = 1904166624;
                        v53 = (unsigned int)(791346458 * v53 + 394843719);
                        break;
                    }
                }
                else
                {
                    switch (v2)
                    {
                    case 0x8DEB238F:
                        v3 = 918184919;
                        v52 = __ROR8__(v52 ^ v53, 32);
                        break;
                    case 0xBED37BDu:
                        v3 = 1325101890;
                        v53 = (unsigned int)(-1316252713 * v53 + 26433920);
                        break;
                    case 0xE8C3FE5u:
                        v3 = 1231084083;
                        v53 = (unsigned int)(2128931962 * v53 + 196012193);
                        break;
                    case 0x72882DB4u:
                        v52 ^= v53;
                        v3 = -2126896649;
                        break;
                    case 0x8B2458BE:
                        v3 = 114260785;
                        v52 = __ROR8__(v52, 32);
                        break;
                    }
                }
                v2 ^= v3;
            } while (v2 != -1152303016);
            goto LABEL_316;
        case 1LL:
            v4 = 660675447;
            v5 = -2053597133;
            if (retaddrIsBig) {
                v4 = -888001894;//legit wert
            }
            while (1)
            {
                if (v4 > 0x66ADB428)
                {
                    switch (v4)
                    {
                    case 0x6DE625ECu:
                        v5 = 95124402;
                        v7 = __ROL8__(v52, 32);
                        goto LABEL_43;
                    case 0x8DC8A84C:
                        v5 = 1397736980;
                        v53 = (unsigned int)(17937816 * v53 + 502857703);
                        break;
                    case 0xDE876E58:
                        v5 = -1205151120;
                        v7 = __ROR8__(v52, 32);
                    LABEL_43:
                        v52 = v7;
                        break;
                    }
                }
                else
                {
                    if (v4 != 1722659880)
                    {
                        if (v4 != 261412494)
                        {
                            switch (v4)
                            {
                            case 0x27611B77u:
                                v53 = (unsigned int)v52;
                                v5 = 204721257;
                                break;
                            case 0x2B52D71Eu:
                                v54 = (unsigned int)(-1807769420 * v53 - 597445928);
                                v6 = __ROL8__(v52, 32);
                                v52 = v6 ^ v54;
                                v53 = (unsigned int)v6 ^ (unsigned int)v54;
                                v5 = -1499824302;
                                break;
                            case 0x59258FECu:
                                v5 = 246496120;
                                v53 = (unsigned int)(1601909380 * v53 + 376262430);
                                break;
                            }
                            goto LABEL_44;
                        }
                        v5 = 545908193;
                        v53 = (unsigned int)(-504650155 * v52 + 1738583875);
                        v7 = __ROR8__(v52, 32);
                        goto LABEL_43;
                    }
                    v52 ^= v53;
                    v5 = 189501892;
                }
            LABEL_44:
                v4 ^= v5;
                if (v4 == 1749900894)
                    goto LABEL_316;
            }
        case 2LL:
            v8 = -491906180;
            v9 = -7224882;
            if (false)
            {
                v8 = 2114768486;
            }
            do
            {
                switch (v8)
                {
                case 518440219:
                    v53 = (unsigned int)(691598882 * v52 - 563734325);
                    v9 = 226869046;
                    v52 = __ROL8__(__ROL8__(v52, 32) ^ v53, 32);
                    break;
                case 1244810051:
                    v9 = 259653529;
                    v53 = static_cast<uint32_t>(331326231 * v53 + 23673370);
                    break;
                case -1470550873:
                    v9 = 770117671;
                    v53 = static_cast<uint32_t>(331326231 * v53 + 23673370);
                    break;
                case -491906180:
                    v53 = (unsigned int)(119156141 * v52 - 770314270);
                    v52 = __ROR8__(v52, 32) ^ v53;
                    v9 = -62333337;
                    break;
                }
                v8 ^= v9;
            } while (v8 != 325286445);
            goto LABEL_316;
        case 3LL:
            v10 = 617725989;
            v11 = -745725959;
            if (false)
            {
                v10 = -2090608248;
            }
            while (1)
            {
                if (v10 > 0x24D1C025)
                {
                    switch (v10)
                    {
                    case 0x429B89C8u:
                        v11 = 1094927146;
                        v13 = 1766346885 * v53 - 1012174494;
                        goto LABEL_85;
                    case 0x644154CDu:
                        v11 = 54483382;
                        v53 = (unsigned int)(-830598076 * v53 - 1606521245);
                        break;
                    case 0x913A4E10:
                        v52 ^= v53;
                        v11 = 334970621;
                        goto LABEL_86;
                    }
                }
                else
                {
                    switch (v10)
                    {
                    case 0x24D1C025u:
                        v53 = (unsigned int)v52;
                        v11 = 1716144621;
                        break;
                    case 0x3D8CAE2u:
                        v52 ^= v53;
                        v11 = 179401950;
                        break;
                    case 0x862A67Bu:
                        v11 = 918497535;
                        v13 = 116059748 * v52 + 1159974097;
                    LABEL_85:
                        v53 = v13;
                    LABEL_86:
                        v12 = __ROL8__(v52, 32);
                    LABEL_87:
                        v52 = v12;
                        break;
                    case 0x969BE3Cu:
                        v11 = -1739329492;
                        v53 = (unsigned int)(1801497905 * v52 - 291203075);
                        v12 = __ROR8__(v52, 32);
                        goto LABEL_87;
                    }
                }
                v10 ^= v11;
                if (v10 == -2100465427)
                    goto LABEL_316;
            }
        case 4LL:
            v14 = 2135172155;
            v15 = 106430227;
            do
            {
                if (v14 > 0x6EA8BAE8)
                {
                    switch (v14)
                    {
                    case 0x7F44243Bu:
                        v15 = -1939768772;
                        v53 = (unsigned int)(8765184 * v52 + 78628830);
                        break;
                    case 0xC7D6F950:
                        v53 = (unsigned int)v52;
                        v15 = -1069390290;
                        break;
                    case 0xF3255E07:
                        v15 = -1596830739;
                        v52 = __ROR8__(v52, 32);
                        break;
                    }
                }
                else
                {
                    switch (v14)
                    {
                    case 0x6EA8BAE8u:
                        v15 = 314332228;
                        v53 = (unsigned int)(-1346964338 * v53 + 1699332261);
                        v52 = __ROL8__(v52, 32);
                        break;
                    case 0x7949F7Eu:
                        v15 = 213399329;
                        v53 = (unsigned int)(-1888751842 * v53 - 1018856490);
                        v52 = __ROR8__(v52, 32);
                        break;
                    case 0xB2CA85Fu:
                        v15 = -1814052536;
                        v52 = __ROL8__(v52 ^ v53, 32);
                        break;
                    case 0x4AFF4D82u:
                        v15 = -1085569433;
                        v53 = (unsigned int)(-1069554871 * v52 - 2001770735);
                        v52 = __ROR8__(v52, 32);
                        break;
                    case 0x53F715EAu:
                        v52 ^= v53;
                        v15 = -1809716038;
                        break;
                    }
                }
                v14 ^= v15;
            } while (v14 != -1728878313);
            goto LABEL_316;
        case 5LL:
            v16 = -1060124190;
            v17 = 661575635;
            while (v16 != 267875343)
            {
                if (v16 == 271137405)
                {
                    v17 = -1921003845;
                    v52 = __ROL8__(v52, 32);
                }
                else
                {
                    if (v16 != -1655245626)
                    {
                        if (v16 != -1060124190)
                        {
                            if (v16 == -425404207)
                            {
                                v17 = 1503285818;
                                v53 = (unsigned int)(1119826086 * v52 + 988991924);
                                v52 = __ROR8__(v52, 32);
                            }
                            goto LABEL_122;
                        }
                        v55 = (unsigned int)(132219338 * v52 - 2041947905);
                        v18 = __ROL8__(v52, 32);
                        v52 = v18 ^ v55;
                        v17 = -790170721;
                        v19 = -1143138413 * (v18 ^ v55) + 154192296;
                        goto LABEL_121;
                    }
                    v17 = 95142508;
                    v52 = __ROL8__(v52 ^ v53, 32);
                }
            LABEL_122:
                v16 ^= v17;
                if (v16 == -1728235862)
                    goto LABEL_316;
            }
            v17 = -889731599;
            v19 = 223128853 * v52 + 1755225231;
        LABEL_121:
            v53 = v19;
            goto LABEL_122;
        case 6LL:
            v20 = 1895346683;
            v21 = 418947001;
            do
            {
                if (v20 > 0x37DDC45A)
                {
                    switch (v20)
                    {
                    case 0x70F8B1FBu:
                        v53 = (unsigned int)v52;
                        v21 = 263328172;
                        break;
                    case 0x7F4AA057u:
                        v21 = 2145248564;
                        v53 = (unsigned int)(1807498829 * v53 + 1377314933);
                        break;
                    case 0xA7ED7A40:
                        v21 = -1746790300;
                        v52 = __ROR8__(v52 ^ v53, 32);
                        break;
                    }
                }
                else
                {
                    switch (v20)
                    {
                    case 0x37DDC45Au:
                        v21 = 45580216;
                        v53 = (unsigned int)(672918983 * v53 + 581323356);
                        v52 = __ROR8__(v52, 32);
                        break;
                    case 0x974563u:
                        v21 = 185448874;
                        v52 = __ROR8__(v52, 32);
                        break;
                    case 0xB9AFCC9u:
                        v52 ^= v53;
                        v21 = 581385833;
                        break;
                    case 0x293DC2A0u:
                        v21 = -1898923808;
                        v53 = (unsigned int)(-731896304 * v52 + 121378778);
                        v52 = __ROL8__(v52, 32);
                        break;
                    case 0x2B261838u:
                        v21 = 1406383041;
                        v53 = (unsigned int)(-379229597 * v53 + 192823981);
                        v52 = __ROR8__(v52, 32);
                        break;
                    }
                }
                v20 ^= v21;
            } while (v20 != 806314532);
            goto LABEL_316;
        case 7LL:
            v22 = 230532316;
            v23 = -464864257;
            if (retaddrIsBig) {
                v22 = -716159479; //legit wert
            }
            while (1)
            {
                if (v22 > 0x6B2BBBF2)
                {
                    if (v22 != -1275976962)
                    {
                        if (v22 == -1256629626)
                        {
                            v52 = __ROL8__(v52, 32) ^ v53;
                            v23 = 1794880900;
                        }
                        else if (v22 == -538775806)
                        {
                            v23 = 180212815;
                            v52 = __ROR8__(v52, 32);
                        }
                        goto LABEL_164;
                    }
                    v23 = -266439830;
                    v24 = -1840991455 * v52 + 544562082;
                    goto LABEL_163;
                }
                if (v22 == 1798028274)
                    break;
                if (v22 == 230532316)
                {
                    v23 = 947795013;
                    v24 = -1259945050 * v52 + 550769224;
                LABEL_163:
                    v53 = v24;
                    goto LABEL_164;
                }
                if (v22 != 902008985)
                {
                    if (v22 != 1427218897)
                    {
                        if (v22 == 1645087488)
                        {
                            v53 = (unsigned int)v52;
                            v23 = 153465074;
                        }
                        goto LABEL_164;
                    }
                    v23 = -467555542;
                    v24 = 9662710 * v53 - 1052055890;
                    goto LABEL_163;
                }
                v52 = __ROR8__(v52, 32) ^ v53;
                v23 = 1473092505;
            LABEL_164:
                v22 ^= v23;
                if (v22 == -715179187)
                    goto LABEL_316;
            }
            v23 = -567090828;
            v24 = 1888766672 * v53 - 157850889;
            goto LABEL_163;
        case 8LL:
            v25 = -1401059616;
            v26 = 15852479;
            if (retaddrIsBig) {
                v25 = 936184625; //legit wert
            }
            do
            {
                if (v25 > 0x8B5FA800)
                {
                    switch (v25)
                    {
                    case 0xAC7D86E0:
                        v53 = (unsigned int)v52;
                        v26 = 656551648;
                        break;
                    case 0xAE7D42E9:
                        v26 = 142135222;
                        v53 = (unsigned int)(1738929306 * v52 - 1889209659);
                        v52 = __ROL8__(v52, 32);
                        break;
                    case 0xC6BBFF60:
                        v26 = -1083969707;
                        v53 = (unsigned int)(-1020796705 * v53 + 2045927347);
                        v52 = __ROL8__(v52, 32);
                        break;
                    }
                }
                else
                {
                    switch (v25)
                    {
                    case 0x8B5FA800:
                        v56 = (unsigned int)(-2053775009 * v53 + 288571645);
                        v27 = __ROL8__(v52, 32);
                        v52 = v27 ^ v56;
                        v53 = (unsigned int)v27 ^ (unsigned int)v56;
                        v26 = 1306810208;
                        break;
                    case 0xE90C8DCu:
                        v26 = 1066419564;
                        v53 = (unsigned int)(41840847 * v53 + 577215711);
                        v52 = __ROL8__(v52, 32);
                        break;
                    case 0x79D81035u:
                        v52 ^= v53;
                        v26 = -119622870;
                        break;
                    case 0x8106A31F:
                        v26 = 95086830;
                        v52 = __ROR8__(v52, 32);
                        break;
                    }
                }
                v25 ^= v26;
            } while (v25 != -2069083151);
            goto LABEL_316;
        case 9LL:
            v28 = 1408056962;
            v29 = -849101259;
            do
            {
                switch (v28)
                {
                case 1408056962:
                    v53 = (unsigned int)(-1296148431 * v52 + 1678822514);
                    v52 = __ROR8__(v52, 32) ^ v53;
                    v29 = -2107510509;
                    break;
                case 1730227930:
                    v29 = 1482056554;
                    v52 = __ROL8__(v52 ^ v53, 32);
                    break;
                case -1485486187:
                    v29 = 2078473979;
                    v53 = (unsigned int)(16464864 * v53 + 1779911046);
                    break;
                case -1170041866:
                    v29 = 80364887;
                    v53 = (unsigned int)(-288265349 * v52 + 2089062501);
                    break;
                case -779300975:
                    v29 = -1230118581;
                    v53 = (unsigned int)(-1265239898 * v52 + 1012616060);
                    v52 = __ROL8__(v52, 32);
                    break;
                }
                v28 ^= v29;
            } while (v28 != 1064783280);
            goto LABEL_316;
        case 10LL:
            v30 = 1190021800;
            v31 = 778282410;
            if (retaddrIsBig) {
                v30 = -842283985; //legit wert
            }
            do
            {
                if (v30 > 0x46EE4AA8)
                {
                    switch (v30)
                    {
                    case 0x4B4B6D69u:
                        v53 = (unsigned int)v52;
                        v31 = 1175507701;
                        break;
                    case 0x66EB65A0u:
                        v31 = -886195675;
                        v53 = (unsigned int)(-171682270 * v53 + 149894501);
                        break;
                    case 0x92B4798C:
                        v31 = -2031705211;
                        v53 = (unsigned int)(1087282763 * v53 - 1367069040);
                        v52 = __ROL8__(v52, 32);
                        break;
                    }
                }
                else
                {
                    switch (v30)
                    {
                    case 0x46EE4AA8u:
                        v53 = (unsigned int)(64494261 * v52 + 1900749149);
                        v52 = __ROR8__(v52, 32) ^ v53;
                        v31 = 228927425;
                        break;
                    case 0x6A75EE5u:
                        v52 ^= v53;
                        v31 = 1038716998;
                        break;
                    case 0xD5BBF9Cu:
                        v31 = 201122169;
                        v53 = (unsigned int)(-438684520 * v53 - 1238343084);
                        v52 = __ROL8__(v52, 32);
                        break;
                    case 0x3B4ECEA3u:
                        v31 = 1180324910;
                        v52 = __ROL8__(v52, 32);
                        break;
                    }
                }
                v30 ^= v31;
            } while (v30 != 2098502285);
            goto LABEL_316;
        case 11LL:
            v32 = 645655242;
            v33 = 140830803;
            if (retaddrIsBig) {
                v32 = 630914689; //legit wert
            }
            while (1)
            {
                if (v32 > 0x756CE75D)
                {
                    if (v32 == -1680385751)
                    {
                        v33 = -2119510370;
                        v35 = 2145370855 * v53 + 776641312;
                    }
                    else
                    {
                        if (v32 != -853216555)
                        {
                            if (v32 == -328230210)
                            {
                                v33 = -973193908;
                                v53 = (unsigned int)(854374647 * v52 + 1837472016);
                                v52 = __ROL8__(v52, 32);
                            }
                            goto LABEL_237;
                        }
                        v33 = -1203235448;
                        v35 = -730236885 * v53 + 169792528;
                    }
                }
                else
                {
                    if (v32 != 1970071389)
                    {
                        switch (v32)
                        {
                        case 0x1293744Cu:
                            v52 ^= v53;
                            v33 = 919310305;
                            break;
                        case 0x2458FBADu:
                            v33 = 999083583;
                            v52 = __ROL8__(v52, 32);
                            break;
                        case 0x267BEACAu:
                            v53 = (unsigned int)v52;
                            v33 = -346089441;
                            break;
                        case 0x701B93F6u:
                            v33 = 1653139386;
                            v52 = __ROR8__(v52, 32);
                            break;
                        }
                        goto LABEL_237;
                    }
                    v34 = __ROL8__(v52, 32);
                    v52 = v34 ^ v53;
                    v33 = 91714731;
                    v35 = -1176512972 * (v34 ^ v53) - 1765643742;
                }
                v53 = v35;
            LABEL_237:
                v32 ^= v33;
                if (v32 == 534001042)
                    goto LABEL_316;
            }
        case 12LL:
            v36 = -658387073;
            v37 = -1579206344;
            if (retaddrIsBig) {
                v36 = 607249829; //legit wert
            }
            do
            {
                if (v36 > 0x7C360A1C)
                {
                    switch (v36)
                    {
                    case 0x95BCFD2F:
                        v52 ^= v53;
                        v37 = -890313957;
                        break;
                    case 0x9E48C2F0:
                        v37 = 123387859;
                        v53 = (unsigned int)(43712362 * v53 + 1186415333);
                        v52 = __ROR8__(v52, 32);
                        break;
                    case 0xAFB13B8D:
                        v37 = 266557358;
                        v53 = (unsigned int)(174779216 * v53 + 1962750543);
                        break;
                    case 0xD8C1CF7F:
                        v53 = (unsigned int)v52;
                        v37 = -445090736;
                        break;
                    }
                }
                else
                {
                    switch (v36)
                    {
                    case 0x7C360A1Cu:
                        v37 = 184984173;
                        v52 = __ROR8__(v52, 32);
                        break;
                    case 0x3DB9BB2Fu:
                        v37 = 1099936051;
                        v53 = (unsigned int)(24632919 * v53 - 1590474305);
                        break;
                    case 0x4C0664ADu:
                        v37 = -642082430;
                        v53 = (unsigned int)(1399616130 * v52 + 1890307903);
                        v52 = __ROL8__(v52, 32);
                        break;
                    case 0x5F521E34u:
                        v37 = 1680968503;
                        v52 = __ROL8__(v52, 32);
                        break;
                    case 0x7730A871u:
                        v52 ^= v53;
                        v37 = 993447132;
                        break;
                    }
                }
                v36 ^= v37;
            } while (v36 != 996381955);
            goto LABEL_316;
        case 13LL:
            v38 = -828937925;
            v39 = -2109700284;
            if (retaddrIsBig) {
                v38 = 1607092327; //legit wert
            }
            while (1)
            {
                if (v38 > 0xB11856CB)
                {
                    switch (v38)
                    {
                    case 0xC9CBF67A:
                        v39 = -521458978;
                        v40 = -982233137 * v53 - 667608983;
                        goto LABEL_279;
                    case 0xCE97693B:
                        v53 = (unsigned int)v52;
                        v39 = 123510593;
                        break;
                    case 0xEBCA1A5A:
                        v39 = 440978373;
                        v41 = __ROL8__(v52 ^ v53, 32);
                        goto LABEL_280;
                    }
                }
                else
                {
                    switch (v38)
                    {
                    case 0xB11856CB:
                        v39 = 1523731601;
                        v53 = (unsigned int)(-1581463050 * v53 + 72247220);
                        v41 = __ROL8__(v52, 32);
                    LABEL_280:
                        v52 = v41;
                        break;
                    case 0x2920DCA4u:
                        v52 ^= v53;
                        v53 = (unsigned int)v52;
                        v39 = -1741125009;
                        break;
                    case 0x3D66D6FDu:
                        v39 = 1645584240;
                        v40 = 233088609 * v52 + 1470443078;
                        goto LABEL_279;
                    case 0x42CAA043u:
                        v39 = 1666197599;
                        v40 = -780430287 * v53 + 931128783;
                    LABEL_279:
                        v53 = v40;
                        v41 = __ROR8__(v52, 32);
                        goto LABEL_280;
                    }
                }
                v38 ^= v39;
                if (v38 == -243084897)
                    goto LABEL_316;
            }
        case 14LL:
            v42 = 92938687;
            v43 = -685223004;
            while (v42 <= 0xC9292B99)
            {
                switch (v42)
                {
                case 0xC9292B99:
                    v52 = __ROR8__(v52, 32) ^ v53;
                    v43 = -74571611;
                    break;
                case 0x58A21BFu:
                    v53 = (unsigned int)v52;
                    v43 = -810921886;
                    break;
                case 0x32A70B3Cu:
                    v53 = (unsigned int)(2065059634 * v52 - 2108097223);
                    v43 = -1843071790;
                    v52 = __ROR8__(__ROR8__(v52, 32) ^ v53, 32);
                    break;
                case 0x8D479ACA:
                    v43 = 212249908;
                    v44 = 252673038 * v52 + 465684149;
                LABEL_297:
                    v53 = v44;
                    break;
                }
            LABEL_298:
                v42 ^= v43;
                if (v42 == -1601962002)
                    goto LABEL_316;
            }
            if (v42 != -903843363)
            {
                if (v42 == -507804768)
                {
                    v43 = 15724765;
                    v53 = (unsigned int)(31181193 * v53 + 768556156);
                    v52 = __ROR8__(v52, 32);
                }
                goto LABEL_298;
            }
            v43 = 50944580;
            v44 = 106140909 * v53 + 71579851;
            goto LABEL_297;
        default:
            v45 = -1955903366;
            v46 = 2142671723;
            break;
        }
        while (v45 <= 0x6D3C6429)
        {
            if (v45 == 1832674345)
            {
                v52 = __ROR8__(v52, 32) ^ v53;
                v46 = 1050426691;
            }
            else
            {
                if (v45 != 374553663)
                {
                    if (v45 != 505921842)
                    {
                        if (v45 == 1403017578)
                        {
                            v53 = (unsigned int)(-247123085 * v52 + 1509138071);
                            v52 = __ROL8__(v52, 32) ^ v53;
                            v46 = -1479476053;
                        }
                        goto LABEL_315;
                    }
                    v46 = -830777003;
                    v47 = -1574065540 * v53 - 986305121;
                    goto LABEL_314;
                }
                v46 = 208837513;
                v53 = (unsigned int)(-1911345348 * v52 + 702923134);
                v52 = __ROR8__(v52, 32);
            }
        LABEL_315:
            v45 ^= v46;
            if (v45 == 1533882257)
                goto LABEL_316;
        }
        if (v45 != -1955903366)
        {
            if (v45 == -193944127)
            {
                v46 = -1357018544;
                v52 = __ROR8__(v52, 32);
            }
            goto LABEL_315;
        }
        v46 = -430494637;
        v47 = 27436105 * v52 - 1544613747;
    LABEL_314:
        v53 = v47;
        goto LABEL_315;
    }
LABEL_316:
    v1 = 0;
    return v52 + 0x342720ULL * v1;
   
}

uint64_t pCEntity(uint64_t enrypted_pointer_CG, HANDLE hProcess, uintptr_t base, int a1)
{

        int v1; // ebx
        int v2; // esi
        int v3; // r9d
        int v4; // edi
        int v5; // r11d
        int v6; // r8d
        int v7; // r15d
        int v8; // r13d
        int v9; // r10d
        int v10; // r12d
        int v11; // r14d
        unsigned int v12; // edx
        int v13; // ecx
        unsigned int v14; // edx
        int v15; // ecx
        __int64 v16; // rax
        __int64 v17; // rax
        int v18; // edx
        int v19; // ecx
        unsigned int v20; // edx
        int v21; // ecx
        __int64 v22; // rax
        unsigned int v23; // eax
        unsigned int v24; // edx
        int v25; // ecx
        int v26; // edx
        int v27; // ecx
        __int64 v28; // rax
        unsigned int v29; // eax
        unsigned int v30; // edx
        int v31; // ecx
        unsigned int v32; // edx
        int v33; // ecx
        unsigned int v34; // eax
        unsigned int v35; // edx
        int v36; // ecx
        __int64 v37; // rax
        int v38; // edx
        int v39; // ecx
        unsigned int v40; // edx
        int v41; // ecx
        unsigned int v42; // edx
        int v43; // ecx
        __int64 v44; // rax
        unsigned int v45; // eax
        unsigned int v46; // edx
        int v47; // ecx
        unsigned int v48; // edx
        int v49; // ecx
        unsigned int v50; // eax
        __int64 v51; // rax
        unsigned int v52; // edx
        int v53; // ecx
        unsigned int v54; // eax
        unsigned int v55; // edx
        int v56; // ecx
        unsigned int v57; // eax
        __int64 v58; // rax
        __int64 v59; // rax
        int v60; // edx
        int v61; // ecx
        __int64 v62; // rax
        unsigned int v63; // edx
        int v64; // ecx
        unsigned int v65; // edx
        int v66; // ecx
        int v67; // ecx
        unsigned int v68; // edx
        unsigned int v69; // eax
        __int64 v70; // rax
        unsigned int v71; // edx
        int v72; // ecx
        unsigned int v73; // edx
        int v74; // ecx
        __int64 v75; // rax
        unsigned int v76; // eax
        unsigned int v77; // edx
        int v78; // ecx
        unsigned int v79; // eax
        __int64 v80; // rax
        unsigned int v81; // edx
        int v82; // ecx
        unsigned int v83; // edx
        int v84; // ecx
        __int64 v85; // rax
        unsigned int v86; // edx
        int v87; // ecx
        __int64 v88; // rax
        unsigned int v89; // edx
        int v90; // ecx
        __int64 v91; // rax
        unsigned int v92; // eax
        unsigned int v93; // edx
        int v94; // ecx
        unsigned int v95; // edx
        int v96; // ecx
        __int64 v97; // rax
        int v98; // edx
        int v99; // ecx
        __int64 v100; // rax
        unsigned int v101; // eax
        __int64 v102; // rax
        unsigned int v103; // edx
        int v104; // ecx
        unsigned int v105; // edx
        int v106; // ecx
        unsigned int v107; // ecx
        int v108; // edx
        int v109; // eax
        unsigned int v110; // edx
        int v111; // eax
        __int64 v112; // rdx
        unsigned int v113; // edx
        unsigned int v114; // edx
        int v115; // eax
        unsigned int v116; // edx
        int v117; // eax
        unsigned int v118; // edx
        __int64 v119; // rax
        unsigned int v120; // eax
        unsigned int v121; // edx
        int v122; // eax
        __int64 v123; // rax
        unsigned int v124; // edx
        unsigned int v125; // edx
        __int64 v126; // rax
        unsigned int v127; // edx
        unsigned int v128; // edx
        __int64 v129; // rax
        unsigned int v130; // eax
        unsigned int v131; // edx
        unsigned int v132; // edx
        __int64 v133; // rax
        int v134; // edx
        int v135; // eax
        __int64 v136; // rax
        unsigned int v137; // edx
        unsigned int v138; // edx
        __int64 v139; // rax
        unsigned int v140; // edx
        int v141; // eax
        unsigned int v142; // edx
        int v143; // eax
        int v144; // edx
        int v145; // eax
        unsigned int v146; // edx
        int v147; // eax
        unsigned int v148; // edx
        int v149; // eax
        int v150; // edx
        int v151; // eax
        __int64 v152; // rax
        unsigned int v153; // edx
        int v154; // eax
        unsigned int v155; // edx
        int v156; // eax
        unsigned int v157; // edx
        int v158; // eax
        int v159; // edx
        int v160; // eax
        unsigned int v161; // edx
        int v162; // eax
        unsigned int v163; // edx
        int v164; // eax
        __int64 v165; // rax
        unsigned int v166; // eax
        int v167; // ecx
        __int64 v168; // rdx
        unsigned int v169; // edx
        int v170; // eax
        unsigned int v171; // edx
        int v172; // eax
        unsigned int v173; // edx
        int v174; // eax
        __int64 v175; // rbx
        __int64 v179; // [rsp+88h] [rbp+50h]
        __int64 v180; // [rsp+88h] [rbp+50h]
        __int64 v181; // [rsp+88h] [rbp+50h]
        __int64 v182; // [rsp+88h] [rbp+50h]
        __int64 v183; // [rsp+88h] [rbp+50h]
        __int64 v184; // [rsp+88h] [rbp+50h]
        __int64 v185; // [rsp+88h] [rbp+50h]
        __int64 v186; // [rsp+88h] [rbp+50h]
        __int64 v187; // [rsp+90h] [rbp+58h]
        __int64 v188; // [rsp+90h] [rbp+58h]
        __int64 v189; // [rsp+90h] [rbp+58h]
        __int64 v190; // [rsp+90h] [rbp+58h]
        __int64 v191; // [rsp+90h] [rbp+58h]
        __int64 v192; // [rsp+90h] [rbp+58h]
        __int64 v193; // [rsp+90h] [rbp+58h]
        __int64 v194; // [rsp+90h] [rbp+58h]
        __int64 v195; // [rsp+90h] [rbp+58h]
        __int64 v196; // [rsp+90h] [rbp+58h]

        int maxLocalClients = 2;

        v1 = 0;
        v2 = 1821433004;
        v3 = 44452587;
        v4 = 178183464;
        v5 = 1702382319;
        v6 = -1795615490;
        v7 = -249265863;
        v8 = 1300419157;
        v9 = -2119073988;
        v10 = 54222133;
        v11 = 36603113;
        do
        {
            v179 = enrypted_pointer_CG;
            if (enrypted_pointer_CG)
            {
                v187 = GetSwitchCaseValue(hProcess);
                switch (v187)
                {
                case 0LL:
                    v12 = -182854066;
                    v13 = -478971047;
                   
                    do
                    {
                        if (v12 > 0x8DEB238F)
                        {
                            switch (v12)
                            {
                            case 0xF3B20C43:
                                v187 = (unsigned int)v179;
                                v13 = 166269469;
                                break;
                            case 0xF519DE4E:
                                v13 = -2020477958;
                                v187 = (unsigned int)(1584075655 * v179 + 586718870);
                                v179 = __ROR8__(v179, 32);
                                break;
                            case 0xFA5B1E5E:
                                v13 = 1904166624;
                                v187 = (unsigned int)(791346458 * v187 + 394843719);
                                break;
                            }
                        }
                        else
                        {
                            switch (v12)
                            {
                            case 0x8DEB238F:
                                v13 = 918184919;
                                v179 = __ROR8__(v179 ^ v187, 32);
                                break;
                            case 0xBED37BDu:
                                v13 = 1325101890;
                                v187 = (unsigned int)(-1316252713 * v187 + 26433920);
                                break;
                            case 0xE8C3FE5u:
                                v13 = 1231084083;
                                v187 = (unsigned int)(2128931962 * v187 + 196012193);
                                break;
                            case 0x72882DB4u:
                                v179 ^= v187;
                                v13 = -2126896649;
                                break;
                            case 0x8B2458BE:
                                v13 = 114260785;
                                v179 = __ROR8__(v179, 32);
                                break;
                            }
                        }
                        v12 ^= v13;
                    } while (v12 != -1152303016);
                    goto LABEL_317;
                case 1LL:
                    v14 = 660675447;
                    v15 = -2053597133;
                   
                    while (1)
                    {
                        if (v14 > 0x66ADB428)
                        {
                            switch (v14)
                            {
                            case 0x6DE625ECu:
                                v15 = 95124402;
                                v17 = __ROL8__(v179, 32);
                                goto LABEL_44;
                            case 0x8DC8A84C:
                                v15 = 1397736980;
                                v187 = (unsigned int)(17937816 * v187 + 502857703);
                                break;
                            case 0xDE876E58:
                                v15 = -1205151120;
                                v17 = __ROR8__(v179, 32);
                            LABEL_44:
                                v179 = v17;
                                break;
                            }
                        }
                        else
                        {
                            if (v14 != 1722659880)
                            {
                                if (v14 != 261412494)
                                {
                                    switch (v14)
                                    {
                                    case 0x27611B77u:
                                        v187 = (unsigned int)v179;
                                        v15 = 204721257;
                                        break;
                                    case 0x2B52D71Eu:
                                        v188 = (unsigned int)(-1807769420 * v187 - 597445928);
                                        v16 = __ROL8__(v179, 32);
                                        v179 = v16 ^ v188;
                                        v187 = (unsigned int)v16 ^ (unsigned int)v188;
                                        v15 = -1499824302;
                                        break;
                                    case 0x59258FECu:
                                        v15 = 246496120;
                                        v187 = (unsigned int)(1601909380 * v187 + 376262430);
                                        break;
                                    }
                                    goto LABEL_45;
                                }
                                v15 = 545908193;
                                v187 = (unsigned int)(-504650155 * v179 + 1738583875);
                                v17 = __ROR8__(v179, 32);
                                goto LABEL_44;
                            }
                            v179 ^= v187;
                            v15 = 189501892;
                        }
                    LABEL_45:
                        v14 ^= v15;
                        if (v14 == 1749900894)
                            goto LABEL_317;
                    }
                case 2LL:
                    v18 = -491906180;
                    v19 = -7224882;
                   
                    do
                    {
                        switch (v18)
                        {
                        case 518440219:
                            v187 = (unsigned int)(691598882 * v179 - 563734325);
                            v19 = 226869046;
                            v179 = __ROL8__(__ROL8__(v179, 32) ^ v187, 32);
                            break;
                        case 1244810051:
                            v19 = 259653529;
                            v187 = (331326231 * v187 + 23673370) & 0xFFFFFFFF;
                            break;
                        case -1470550873:
                            v19 = 770117671;
                            v187 = (-1540283608 * v187 + 2010879009) & 0xFFFFFFFF;             
                            break;
                        case -491906180:
                            v187 = (unsigned int)(119156141 * v179 - 770314270);
                            v179 = __ROR8__(v179, 32) ^ v187;
                            v19 = -62333337;
                            break;
                        }
                        v18 ^= v19;
                    } while (v18 != 325286445);
                    goto LABEL_317;
                case 3LL:
                    v20 = 617725989;
                    v21 = -745725959;
                  
                    while (1)
                    {
                        if (v20 > 0x24D1C025)
                        {
                            switch (v20)
                            {
                            case 0x429B89C8u:
                                v21 = 1094927146;
                                v23 = 1766346885 * v187 - 1012174494;
                                goto LABEL_86;
                            case 0x644154CDu:
                                v21 = 54483382;
                                v187 = (unsigned int)(-830598076 * v187 - 1606521245);
                                break;
                            case 0x913A4E10:
                                v179 ^= v187;
                                v21 = 334970621;
                                goto LABEL_87;
                            }
                        }
                        else
                        {
                            switch (v20)
                            {
                            case 0x24D1C025u:
                                v187 = (unsigned int)v179;
                                v21 = 1716144621;
                                break;
                            case 0x3D8CAE2u:
                                v179 ^= v187;
                                v21 = 179401950;
                                break;
                            case 0x862A67Bu:
                                v21 = 918497535;
                                v23 = 116059748 * v179 + 1159974097;
                            LABEL_86:
                                v187 = v23;
                            LABEL_87:
                                v22 = __ROL8__(v179, 32);
                            LABEL_88:
                                v179 = v22;
                                break;
                            case 0x969BE3Cu:
                                v21 = -1739329492;
                                v187 = (unsigned int)(1801497905 * v179 - 291203075);
                                v22 = __ROR8__(v179, 32);
                                goto LABEL_88;
                            }
                        }
                        v20 ^= v21;
                        if (v20 == -2100465427)
                            goto LABEL_317;
                    }
                case 4LL:
                    v24 = 2135172155;
                    v25 = 106430227;
                    do
                    {
                        if (v24 > 0x6EA8BAE8)
                        {
                            switch (v24)
                            {
                            case 0x7F44243Bu:
                                v25 = -1939768772;
                                v187 = (unsigned int)(8765184 * v179 + 78628830);
                                break;
                            case 0xC7D6F950:
                                v187 = (unsigned int)v179;
                                v25 = -1069390290;
                                break;
                            case 0xF3255E07:
                                v25 = -1596830739;
                                v179 = __ROR8__(v179, 32);
                                break;
                            }
                        }
                        else
                        {
                            switch (v24)
                            {
                            case 0x6EA8BAE8u:
                                v25 = 314332228;
                                v187 = (unsigned int)(-1346964338 * v187 + 1699332261);
                                v179 = __ROL8__(v179, 32);
                                break;
                            case 0x7949F7Eu:
                                v25 = 213399329;
                                v187 = (unsigned int)(-1888751842 * v187 - 1018856490);
                                v179 = __ROR8__(v179, 32);
                                break;
                            case 0xB2CA85Fu:
                                v25 = -1814052536;
                                v179 = __ROL8__(v179 ^ v187, 32);
                                break;
                            case 0x4AFF4D82u:
                                v25 = -1085569433;
                                v187 = (unsigned int)(-1069554871 * v179 - 2001770735);
                                v179 = __ROR8__(v179, 32);
                                break;
                            case 0x53F715EAu:
                                v179 ^= v187;
                                v25 = -1809716038;
                                break;
                            }
                        }
                        v24 ^= v25;
                    } while (v24 != -1728878313);
                    goto LABEL_317;
                case 5LL:
                    v26 = -1060124190;
                    v27 = 661575635;
                    while (v26 != 267875343)
                    {
                        if (v26 == 271137405)
                        {
                            v27 = -1921003845;
                            v179 = __ROL8__(v179, 32);
                        }
                        else
                        {
                            if (v26 != -1655245626)
                            {
                                if (v26 != -1060124190)
                                {
                                    if (v26 == -425404207)
                                    {
                                        v27 = 1503285818;
                                        v187 = (unsigned int)(1119826086 * v179 + 988991924);
                                        v179 = __ROR8__(v179, 32);
                                    }
                                    goto LABEL_123;
                                }
                                v189 = (unsigned int)(132219338 * v179 - 2041947905);
                                v28 = __ROL8__(v179, 32);
                                v179 = v28 ^ v189;
                                v27 = -790170721;
                                v29 = -1143138413 * (v28 ^ v189) + 154192296;
                                goto LABEL_122;
                            }
                            v27 = 95142508;
                            v179 = __ROL8__(v179 ^ v187, 32);
                        }
                    LABEL_123:
                        v26 ^= v27;
                        if (v26 == -1728235862)
                            goto LABEL_317;
                    }
                    v27 = -889731599;
                    v29 = 223128853 * v179 + 1755225231;
                LABEL_122:
                    v187 = v29;
                    goto LABEL_123;
                case 6LL:
                    v30 = 1895346683;
                    v31 = 418947001;
                    do
                    {
                        if (v30 > 0x37DDC45A)
                        {
                            switch (v30)
                            {
                            case 0x70F8B1FBu:
                                v187 = (unsigned int)v179;
                                v31 = 263328172;
                                break;
                            case 0x7F4AA057u:
                                v31 = 2145248564;
                                v187 = (unsigned int)(1807498829 * v187 + 1377314933);
                                break;
                            case 0xA7ED7A40:
                                v31 = -1746790300;
                                v179 = __ROR8__(v179 ^ v187, 32);
                                break;
                            }
                        }
                        else
                        {
                            switch (v30)
                            {
                            case 0x37DDC45Au:
                                v31 = 45580216;
                                v187 = (unsigned int)(672918983 * v187 + 581323356);
                                v179 = __ROR8__(v179, 32);
                                break;
                            case 0x974563u:
                                v31 = 185448874;
                                v179 = __ROR8__(v179, 32);
                                break;
                            case 0xB9AFCC9u:
                                v179 ^= v187;
                                v31 = 581385833;
                                break;
                            case 0x293DC2A0u:
                                v31 = -1898923808;
                                v187 = (unsigned int)(-731896304 * v179 + 121378778);
                                v179 = __ROL8__(v179, 32);
                                break;
                            case 0x2B261838u:
                                v31 = 1406383041;
                                v187 = (unsigned int)(-379229597 * v187 + 192823981);
                                v179 = __ROR8__(v179, 32);
                                break;
                            }
                        }
                        v30 ^= v31;
                    } while (v30 != 806314532);
                    goto LABEL_317;
                case 7LL:
                    v32 = 230532316;
                    v33 = -464864257;
                  
                    while (1)
                    {
                        if (v32 > 0x6B2BBBF2)
                        {
                            if (v32 != -1275976962)
                            {
                                if (v32 == -1256629626)
                                {
                                    v179 = __ROL8__(v179, 32) ^ v187;
                                    v33 = 1794880900;
                                }
                                else if (v32 == -538775806)
                                {
                                    v33 = 180212815;
                                    v179 = __ROR8__(v179, 32);
                                }
                                goto LABEL_165;
                            }
                            v33 = -266439830;
                            v34 = -1840991455 * v179 + 544562082;
                            goto LABEL_164;
                        }
                        if (v32 == 1798028274)
                            break;
                        if (v32 == 230532316)
                        {
                            v33 = 947795013;
                            v34 = -1259945050 * v179 + 550769224;
                        LABEL_164:
                            v187 = v34;
                            goto LABEL_165;
                        }
                        if (v32 != 902008985)
                        {
                            if (v32 != 1427218897)
                            {
                                if (v32 == 1645087488)
                                {
                                    v187 = (unsigned int)v179;
                                    v33 = 153465074;
                                }
                                goto LABEL_165;
                            }
                            v33 = -467555542;
                            v34 = 9662710 * v187 - 1052055890;
                            goto LABEL_164;
                        }
                        v179 = __ROR8__(v179, 32) ^ v187;
                        v33 = 1473092505;
                    LABEL_165:
                        v32 ^= v33;
                        if (v32 == -715179187)
                            goto LABEL_317;
                    }
                    v33 = -567090828;
                    v34 = 1888766672 * v187 - 157850889;
                    goto LABEL_164;
                case 8LL:
                    v35 = -1401059616;
                    v36 = 15852479;
                   
                    do
                    {
                        if (v35 > 0x8B5FA800)
                        {
                            switch (v35)
                            {
                            case 0xAC7D86E0:
                                v187 = (unsigned int)v179;
                                v36 = 656551648;
                                break;
                            case 0xAE7D42E9:
                                v36 = 142135222;
                                v187 = (unsigned int)(1738929306 * v179 - 1889209659);
                                v179 = __ROL8__(v179, 32);
                                break;
                            case 0xC6BBFF60:
                                v36 = -1083969707;
                                v187 = (unsigned int)(-1020796705 * v187 + 2045927347);
                                v179 = __ROL8__(v179, 32);
                                break;
                            }
                        }
                        else
                        {
                            switch (v35)
                            {
                            case 0x8B5FA800:
                                v190 = (unsigned int)(-2053775009 * v187 + 288571645);
                                v37 = __ROL8__(v179, 32);
                                v179 = v37 ^ v190;
                                v187 = (unsigned int)v37 ^ (unsigned int)v190;
                                v36 = 1306810208;
                                break;
                            case 0xE90C8DCu:
                                v36 = 1066419564;
                                v187 = (unsigned int)(41840847 * v187 + 577215711);
                                v179 = __ROL8__(v179, 32);
                                break;
                            case 0x79D81035u:
                                v179 ^= v187;
                                v36 = -119622870;
                                break;
                            case 0x8106A31F:
                                v36 = 95086830;
                                v179 = __ROR8__(v179, 32);
                                break;
                            }
                        }
                        v35 ^= v36;
                    } while (v35 != -2069083151);
                    goto LABEL_317;
                case 9LL:
                    v38 = 1408056962;
                    v39 = -849101259;
                    do
                    {
                        switch (v38)
                        {
                        case 1408056962:
                            v187 = (unsigned int)(-1296148431 * v179 + 1678822514);
                            v179 = __ROR8__(v179, 32) ^ v187;
                            v39 = -2107510509;
                            break;
                        case 1730227930:
                            v39 = 1482056554;
                            v179 = __ROL8__(v179 ^ v187, 32);
                            break;
                        case -1485486187:
                            v39 = 2078473979;
                            v187 = (unsigned int)(16464864 * v187 + 1779911046);
                            break;
                        case -1170041866:
                            v39 = 80364887;
                            v187 = (unsigned int)(-288265349 * v179 + 2089062501);
                            break;
                        case -779300975:
                            v39 = -1230118581;
                            v187 = (unsigned int)(-1265239898 * v179 + 1012616060);
                            v179 = __ROL8__(v179, 32);
                            break;
                        }
                        v38 ^= v39;
                    } while (v38 != 1064783280);
                    goto LABEL_317;
                case 10LL:     
                    v40 = 1190021800;
                    v41 = 778282410;
                  
                    do
                    {
                        if (v40 > 0x46EE4AA8)
                        {
                            switch (v40)
                            {
                            case 0x4B4B6D69u:
                                v187 = (unsigned int)v179;
                                v41 = 1175507701;
                                break;
                            case 0x66EB65A0u:
                                v41 = -886195675;
                                v187 = (unsigned int)(-171682270 * v187 + 149894501);
                                break;
                            case 0x92B4798C:
                                v41 = -2031705211;
                                v187 = (unsigned int)(1087282763 * v187 - 1367069040);
                                v179 = __ROL8__(v179, 32);
                                break;
                            }
                        }
                        else
                        {
                            switch (v40)
                            {
                            case 0x46EE4AA8u:
                                v187 = (unsigned int)(64494261 * v179 + 1900749149);
                                v179 = __ROR8__(v179, 32) ^ v187;
                                v41 = 228927425;
                                break;
                            case 0x6A75EE5u:
                                v179 ^= v187;
                                v41 = 1038716998;
                                break;
                            case 0xD5BBF9Cu:
                                v41 = 201122169;
                                v187 = (unsigned int)(-438684520 * v187 - 1238343084);
                                v179 = __ROL8__(v179, 32);
                                break;
                            case 0x3B4ECEA3u:
                                v41 = 1180324910;
                                v179 = __ROL8__(v179, 32);
                                break;
                            }
                        }
                        v40 ^= v41;
                    } while (v40 != 2098502285);
                    goto LABEL_317;
                case 11LL:
                    v42 = 645655242;
                    v43 = 140830803;
                  
                    while (1)
                    {
                        if (v42 > 0x756CE75D)
                        {
                            if (v42 == -1680385751)
                            {
                                v43 = -2119510370;
                                v45 = 2145370855 * v187 + 776641312;
                            }
                            else
                            {
                                if (v42 != -853216555)
                                {
                                    if (v42 == -328230210)
                                    {
                                        v43 = -973193908;
                                        v187 = (unsigned int)(854374647 * v179 + 1837472016);
                                        v179 = __ROL8__(v179, 32);
                                    }
                                    goto LABEL_238;
                                }
                                v43 = -1203235448;
                                v45 = -730236885 * v187 + 169792528;
                            }
                        }
                        else
                        {
                            if (v42 != 1970071389)
                            {
                                switch (v42)
                                {
                                case 0x1293744Cu:
                                    v179 ^= v187;
                                    v43 = 919310305;
                                    break;
                                case 0x2458FBADu:
                                    v43 = 999083583;
                                    v179 = __ROL8__(v179, 32);
                                    break;
                                case 0x267BEACAu:
                                    v187 = (unsigned int)v179;
                                    v43 = -346089441;
                                    break;
                                case 0x701B93F6u:
                                    v43 = 1653139386;
                                    v179 = __ROR8__(v179, 32);
                                    break;
                                }
                                goto LABEL_238;
                            }
                            v44 = __ROL8__(v179, 32);
                            v179 = v44 ^ v187;
                            v43 = 91714731;
                            v45 = -1176512972 * (v44 ^ v187) - 1765643742;
                        }
                        v187 = v45;
                    LABEL_238:
                        v42 ^= v43;
                        if (v42 == 534001042)
                            goto LABEL_317;
                    }
                case 12LL:
                    v46 = -658387073;
                    v47 = -1579206344;
                    
                    do
                    {
                        if (v46 > 0x7C360A1C)
                        {
                            switch (v46)
                            {
                            case 0x95BCFD2F:
                                v179 ^= v187;
                                v47 = -890313957;
                                break;
                            case 0x9E48C2F0:
                                v47 = 123387859;
                                v187 = (unsigned int)(43712362 * v187 + 1186415333);
                                v179 = __ROR8__(v179, 32);
                                break;
                            case 0xAFB13B8D:
                                v47 = 266557358;
                                v187 = (unsigned int)(174779216 * v187 + 1962750543);
                                break;
                            case 0xD8C1CF7F:
                                v187 = (unsigned int)v179;
                                v47 = -445090736;
                                break;
                            }
                        }
                        else
                        {
                            switch (v46)
                            {
                            case 0x7C360A1Cu:
                                v47 = 184984173;
                                v179 = __ROR8__(v179, 32);
                                break;
                            case 0x3DB9BB2Fu:
                                v47 = 1099936051;
                                v187 = (unsigned int)(24632919 * v187 - 1590474305);
                                break;
                            case 0x4C0664ADu:
                                v47 = -642082430;
                                v187 = (unsigned int)(1399616130 * v179 + 1890307903);
                                v179 = __ROL8__(v179, 32);
                                break;
                            case 0x5F521E34u:
                                v47 = 1680968503;
                                v179 = __ROL8__(v179, 32);
                                break;
                            case 0x7730A871u:
                                v179 ^= v187;
                                v47 = 993447132;
                                break;
                            }
                        }
                        v46 ^= v47;
                    } while (v46 != 996381955);
                    goto LABEL_317;
                case 13LL:
                    v48 = -828937925;
                    v49 = -2109700284;
                   
                    while (1)
                    {
                        if (v48 > 0xB11856CB)
                        {
                            switch (v48)
                            {
                            case 0xC9CBF67A:
                                v49 = -521458978;
                                v50 = -982233137 * v187 - 667608983;
                                goto LABEL_280;
                            case 0xCE97693B:
                                v187 = (unsigned int)v179;
                                v49 = 123510593;
                                break;
                            case 0xEBCA1A5A:
                                v49 = 440978373;
                                v51 = __ROL8__(v179 ^ v187, 32);
                                goto LABEL_281;
                            }
                        }
                        else
                        {
                            switch (v48)
                            {
                            case 0xB11856CB:
                                v49 = 1523731601;
                                v187 = (unsigned int)(-1581463050 * v187 + 72247220);
                                v51 = __ROL8__(v179, 32);
                            LABEL_281:
                                v179 = v51;
                                break;
                            case 0x2920DCA4u:
                                v179 ^= v187;
                                v187 = (unsigned int)v179;
                                v49 = -1741125009;
                                break;
                            case 0x3D66D6FDu:
                                v49 = 1645584240;
                                v50 = 233088609 * v179 + 1470443078;
                                goto LABEL_280;
                            case 0x42CAA043u:
                                v49 = 1666197599;
                                v50 = -780430287 * v187 + 931128783;
                            LABEL_280:
                                v187 = v50;
                                v51 = __ROR8__(v179, 32);
                                goto LABEL_281;
                            }
                        }
                        v48 ^= v49;
                        if (v48 == -243084897)
                            goto LABEL_317;
                    }
                case 14LL:
                    v52 = 92938687;
                    v53 = -685223004;
                    while (v52 <= 0xC9292B99)
                    {
                        switch (v52)
                        {
                        case 0xC9292B99:
                            v179 = __ROR8__(v179, 32) ^ v187;
                            v53 = -74571611;
                            break;
                        case 0x58A21BFu:
                            v187 = (unsigned int)v179;
                            v53 = -810921886;
                            break;
                        case 0x32A70B3Cu:
                            v187 = (unsigned int)(2065059634 * v179 - 2108097223);
                            v53 = -1843071790;
                            v179 = __ROR8__(__ROR8__(v179, 32) ^ v187, 32);
                            break;
                        case 0x8D479ACA:
                            v53 = 212249908;
                            v54 = 252673038 * v179 + 465684149;
                        LABEL_298:
                            v187 = v54;
                            break;
                        }
                    LABEL_299:
                        v52 ^= v53;
                        if (v52 == -1601962002)
                            goto LABEL_317;
                    }
                    if (v52 != -903843363)
                    {
                        if (v52 == -507804768)
                        {
                            v53 = 15724765;
                            v187 = (unsigned int)(31181193 * v187 + 768556156);
                            v179 = __ROR8__(v179, 32);
                        }
                        goto LABEL_299;
                    }
                    v53 = 50944580;
                    v54 = 106140909 * v187 + 71579851;
                    goto LABEL_298;
                default:
                    v55 = -1955903366;
                    v56 = 2142671723;
                    break;
                }
                while (v55 <= 0x6D3C6429)
                {
                    if (v55 == 1832674345)
                    {
                        v179 = __ROR8__(v179, 32) ^ v187;
                        v56 = 1050426691;
                    }
                    else
                    {
                        if (v55 != 374553663)
                        {
                            if (v55 != 505921842)
                            {
                                if (v55 == 1403017578)
                                {
                                    v187 = (unsigned int)(-247123085 * v179 + 1509138071);
                                    v179 = __ROL8__(v179, 32) ^ v187;
                                    v56 = -1479476053;
                                }
                                goto LABEL_316;
                            }
                            v56 = -830777003;
                            v57 = -1574065540 * v187 - 986305121;
                            goto LABEL_315;
                        }
                        v56 = 208837513;
                        v187 = (unsigned int)(-1911345348 * v179 + 702923134);
                        v179 = __ROR8__(v179, 32);
                    }
                LABEL_316:
                    v55 ^= v56;
                    if (v55 == 1533882257)
                        goto LABEL_317;
                }
                if (v55 != -1955903366)
                {
                    if (v55 == -193944127)
                    {
                        v56 = -1357018544;
                        v179 = __ROR8__(v179, 32);
                    }
                    goto LABEL_316;
                }
                v56 = -430494637;
                v57 = 27436105 * v179 - 1544613747;
            LABEL_315:
                v187 = v57;
                goto LABEL_316;
            }
        LABEL_317:
            if (v179)
            {
                if (a1 < maxLocalClients)
                    v58 = v179 + 3417888LL * a1;
                else
                    v58 = 0LL;


            }
            else
            {
                v58 = 0LL;
            }

            BYTE checkByte =0 ;
            DWORD checkDword= 0;
            uint64_t tempValue = 0;
            uintptr_t address = 0;
            ReadProcessMemory(hProcess, (LPCVOID)(v58 + 1157328), &checkByte, sizeof(checkByte), nullptr);
            ReadProcessMemory(hProcess, (LPCVOID)(v58 + 1157296), &checkDword, sizeof(checkDword), nullptr);
            //if ((*(BYTE*)(v58 + 1157328) & 6) != 0 && v1 == *(DWORD*)(v58 + 1157296))
            if ((checkByte & 6) != 0 && v1 == checkDword) //false
            {
                v59 = v58 + 1203752;
                goto LABEL_663;
            }
            //v180 = *(uint64_t*)(8LL * a1 + 80837472);
            //address = 8ULL * a1 + 80837472ULL;
            address = base + 0x4D17B60 + (8ULL * a1);
            ReadProcessMemory(hProcess, (LPCVOID)address, &tempValue, sizeof(tempValue), nullptr);
            v180 = tempValue;

            if (v180)
            {
                v191 = GetSwitchCaseValue(hProcess);
                switch (v191)
                {
                case 0LL:
                    v60 = 823565520;
                    v61 = 492343627;
                    
                    while (v60 != 38577259)
                    {
                        if (v60 != 823565520)
                        {
                            if (v60 != 828851318)
                            {
                                if (v60 == -1129975960)
                                {
                                    v61 = -121464852;
                                    v191 = (215051184 * v191 + 2010730492) & 0xFFFFFFFF;
                                }
                                goto LABEL_338;
                            }
                            v191 = (unsigned int)(88756900 * v191 + 933478499);
                            v180 = __ROR8__(v180, 32) ^ v191;
                            v61 = 126806196;
                            goto LABEL_337;
                        }
                        v191 = (unsigned int)(-141319033 * v180 - 1690604579);
                        v62 = __ROR8__(v180, 32);
                        v180 = v62 ^ v191;
                        v191 = (v62 ^ v191) & 0xFFFFFFFF;
                        v61 = 7461030;
                    LABEL_338:
                        v60 ^= v61;
                        if (v60 == 921283778)
                            goto LABEL_662;
                    }
                    v61 = 80958019;
                    v191 = (1296735014 * v191 + 137285340) & 0xFFFFFFFF;
                LABEL_337:
                    v180 = __ROR8__(v180, 32);
                    goto LABEL_338;
                case 1LL:
                    v63 = -1975998875;
                    v64 = 1448921146;
                
                    do
                    {
                        if (v63 > 0x2B7C6A9D)
                        {
                            switch (v63)
                            {
                            case 0x712D039Bu:
                                v191 = (unsigned int)v180;
                                v64 = 1818635335;
                                break;
                            case 0x7E41E8E8u:
                                v180 = __ROL8__(v180, 32) ^ v191;
                                v64 = 258796403;
                                break;
                            case 0x8A38A665:
                                v64 = -193376627;
                                v191 = (unsigned int)(-472157018 * v180 - 90928863);
                                break;
                            }
                        }
                        else
                        {
                            switch (v63)
                            {
                            case 0x2B7C6A9Du:
                                v64 = -2131911400;
                                v180 = __ROL8__(__ROL8__(v180, 32) ^ v191, 32);
                                break;
                            case 0xAD67477u:
                                v64 = -1423722364;
                                v191 = (unsigned int)(-764692141 * v191 - 994843541);
                                v180 = __ROL8__(v180, 32);
                                break;
                            case 0xF8BADB0u:
                                v64 = 728542159;
                                v191 = (unsigned int)(14087958 * v180 + 1700830413);
                                break;
                            case 0x1D4B2FDCu:
                                v64 = 909591873;
                                v191 = (unsigned int)(-356675895 * v191 - 802358677);
                                break;
                            }
                        }
                        v63 ^= v64;
                    } while (v63 != -1416497275);
                    goto LABEL_662;
                case 2LL:
                    v65 = -1361814192;
                    v66 = 44452587;
                   
                    do
                    {
                        if (v65 > 0x84DBABD0)
                        {
                            switch (v65)
                            {
                            case 0xAED45D50:
                                v191 = (unsigned int)v180;
                                v66 = -1775290211;
                                break;
                            case 0xB03A0C3A:
                                v191 = (unsigned int)v180;
                                v66 = -288387487;
                                break;
                            case 0xB120D225:
                                v180 = __ROL8__(v180, 32) ^ v191;
                                v66 = 18538015;
                                break;
                            case 0xCDC35128:
                                v66 = -1270798377;
                                v191 = (unsigned int)(1284189861 * v180 - 1409726422);
                                v180 = __ROL8__(v180, 32);
                                break;
                            }
                        }
                        else
                        {
                            switch (v65)
                            {
                            case 0x84DBABD0:
                                v66 = 658807013;
                                v191 = (unsigned int)(-1438266349 * v191 + 1794694572);
                                v180 = __ROR8__(v180, 32);
                                break;
                            case 0x38FB65CDu:
                                v66 = -1982089240;
                                v191 = (unsigned int)(-439572449 * v191 + 1814227452);
                                break;
                            case 0x50E25019u:
                                v180 = __ROR8__(v180, 32) ^ v191;
                                v66 = 766386737;
                                break;
                            case 0x5EF5825Bu:
                                v66 = 236442178;
                                v191 = (unsigned int)(841589274 * v191 + 1351544006);
                                break;
                            case 0x7D4C7228u:
                                v66 = 1101440479;
                                v180 = __ROL8__(v180, 32);
                                break;
                            }
                        }
                        v65 ^= v66;
                    } while (v65 != 1022023671);
                    goto LABEL_662;
                case 3LL:
                    v67 = 9317208;
                    v68 = -1944470796;
                   
                    while (1)
                    {
                        if (v68 > 0xF24DE9D6)
                        {
                            if (v68 == -218064983)
                            {
                                v180 ^= v191;
                                v67 = 21855871;
                                v69 = 1002419580 * v180 - 549351579;
                                goto LABEL_402;
                            }
                            if (v68 == -88769625)
                            {
                                v67 = 963112816;
                                v69 = -1798807866 * v180 + 1593419556;
                            LABEL_402:
                                v191 = v69;
                            LABEL_403:
                                v70 = __ROL8__(v180, 32);
                            LABEL_404:
                                v180 = v70;
                            }
                        }
                        else
                        {
                            switch (v68)
                            {
                            case 0xF24DE9D6:
                                v180 ^= v191;
                                v67 = 1396241585;
                                break;
                            case 0x1B173DEu:
                                v67 = 1700940229;
                                v191 = (unsigned int)(-1175823308 * v191 + 901089883);
                                v70 = __ROR8__(v180, 32);
                                goto LABEL_404;
                            case 0x8C19BAF4:
                                v67 = 2132356445;
                                v69 = -316254171 * v180 - 1208235235;
                                goto LABEL_402;
                            case 0xA1751D67:
                                v67 = 81942235;
                                goto LABEL_403;
                            }
                        }
                        v68 ^= v67;
                        if (v68 == -1516811332)
                            goto LABEL_662;
                    }
                case 4LL:
                    v71 = 162721395;
                    v72 = -360128163;
              
                    do
                    {
                        if (v71 > 0x871BB870)
                        {
                            if (v71 == -512288553)
                            {
                                v191 = (unsigned int)v180;
                                v72 = 1718395047;
                            }
                            else if (v71 == -422977131)
                            {
                                v72 = -1395706215;
                                v180 = __ROR8__(v180 ^ v191, 32);
                            }
                        }
                        else
                        {
                            switch (v71)
                            {
                            case 0x871BB870:
                                v72 = 1641175525;
                                v191 = (unsigned int)(-615647428 * v191 + 185931929);
                                v180 = __ROL8__(v180, 32);
                                break;
                            case 0x9B2EE73u:
                                v191 = (unsigned int)(132586473 * v180 + 1099275482);
                                v180 = __ROL8__(v180, 32) ^ v191;
                                v72 = -389679452;
                                break;
                            case 0x14BCEB56u:
                                v72 = 180913272;
                                v191 = (unsigned int)(1876423119 * v191 + 2012692203);
                                break;
                            case 0x515633C2u:
                                v72 = 1950463062;
                                v191 = (unsigned int)(1991054030 * v191 + 1231923379);
                                v180 = __ROL8__(v180, 32);
                                break;
                            }
                        }
                        v71 ^= v72;
                    } while (v71 != 1241962252);
                    goto LABEL_662;
                case 5LL:
                    v73 = -1946901737;
                    v74 = 1821433004;
              
                    while (1)
                    {
                        if (v73 > 0xA4207E17)
                        {
                            switch (v73)
                            {
                            case 0xA6E75E8D:
                                v74 = 1114489935;
                                v76 = 69775203 * v180 - 1438590907;
                                goto LABEL_453;
                            case 0xB9E8FC70:
                                v74 = 108396383;
                                v191 = (unsigned int)(209498205 * v191 - 958401484);
                                break;
                            case 0xBF9D032F:
                                v74 = -2109729862;
                                v75 = __ROR8__(v180, 32);
                                goto LABEL_454;
                            }
                        }
                        else
                        {
                            switch (v73)
                            {
                            case 0xA4207E17:
                                v74 = 83589932;
                                v76 = -1898427702 * v191 - 1713071270;
                            LABEL_453:
                                v191 = v76;
                                v75 = __ROL8__(v180, 32);
                                goto LABEL_454;
                            case 0x3DDD1095u:
                                v74 = -1353038126;
                                v75 = __ROR8__(v180 ^ v191, 32);
                                goto LABEL_454;
                            case 0x4686FED6u:
                                v180 ^= v191;
                                v74 = 601404411;
                                break;
                            case 0x655E4D2Du:
                                v191 = (unsigned int)v180;
                                v74 = -592006819;
                                break;
                            case 0x8BF4A317:
                                v74 = -848142911;
                                v191 = (unsigned int)(-576055819 * v180 - 1585184923);
                                v75 = __ROR8__(v180, 32);
                            LABEL_454:
                                v180 = v75;
                                break;
                            }
                        }
                        v73 ^= v74;
                        if (v73 == -1836624313)
                            goto LABEL_662;
                    }
                case 6LL:
                    v77 = 1406735124;
                    v78 = -1787769859;
                  
                    while (1)
                    {
                        if (v77 > 0x6B11C26E)
                        {
                            if (v77 != -699210272)
                            {
                                if (v77 == -232483533)
                                {
                                    v80 = __ROR8__(v180, 32);
                                    v181 = v80 ^ v191;
                                    v191 = 268299812 * ((unsigned int)v80 ^ (unsigned int)v191) + 1986535518;
                                    v180 = __ROL8__(v181, 32) ^ v191;
                                    v78 = -55566135;
                                }
                                goto LABEL_478;
                            }
                            v78 = -348079699;
                            v79 = 44416355 * v191 - 1162335614;
                        }
                        else
                        {
                            if (v77 != 1796325998)
                            {
                                switch (v77)
                                {
                                case 0x589DB47u:
                                    v78 = -296583035;
                                    v191 = (unsigned int)(10950705 * v180 + 199910170);
                                    v180 = __ROR8__(v180, 32);
                                    break;
                                case 0xE94B5FAu:
                                    v78 = -265011713;
                                    v180 = __ROR8__(v180, 32);
                                    break;
                                case 0x53D91314u:
                                    v191 = (unsigned int)v180;
                                    v78 = 952684922;
                                    break;
                                }
                                goto LABEL_478;
                            }
                            v78 = -1724557475;
                            v79 = -2047960159 * v191 - 1972334193;
                        }
                        v191 = v79;
                    LABEL_478:
                        v77 ^= v78;
                        if (v77 == -23033851)
                            goto LABEL_662;
                    }
                case 7LL:
                    v81 = 12007180;
                    v82 = 1702382319;
                
                    do
                    {
                        if (v81 > 0x72A9E1D0)
                        {
                            switch (v81)
                            {
                            case 0x77CD3B38u:
                                v180 = __ROR8__(v180, 32) ^ v191;
                                v82 = 131732506;
                                break;
                            case 0xBC711283:
                                v82 = 607485615;
                                v191 = (unsigned int)(-619400760 * v191 + 205257232);
                                break;
                            case 0xDEC92A47:
                                v82 = 178160935;
                                v180 = __ROR8__(v180 ^ v191, 32);
                                break;
                            }
                        }
                        else
                        {
                            switch (v81)
                            {
                            case 0x72A9E1D0u:
                                v82 = -1402942569;
                                v180 = __ROR8__(v180, 32);
                                break;
                            case 0xB7370Cu:
                                v191 = (unsigned int)v180;
                                v82 = 1126968726;
                                break;
                            case 0xFE71322u:
                                v82 = -1516221267;
                                v191 = (unsigned int)(1002951918 * v180 - 1779596728);
                                v180 = __ROR8__(v180, 32);
                                break;
                            case 0x439B1A9Au:
                                v82 = 878059938;
                                v191 = (unsigned int)(976014953 * v191 + 1440717871);
                                break;
                            case 0x70172F22u:
                                v82 = 46059250;
                                v191 = (unsigned int)(-26951093 * v180 + 267301935);
                                break;
                            }
                        }
                        v81 ^= v82;
                    } while (v81 != -732450976);
                    goto LABEL_662;
                case 8LL:
                    v83 = 1717476314;
                    v84 = -1795615490;
                    while (1)
                    {
                        if (v83 > 0x74E12C3C)
                        {
                            switch (v83)
                            {
                            case 0x7A63FF4Eu:
                                v84 = -506581899;
                                goto LABEL_523;
                            case 0x9BADD33B:
                                v180 ^= v191;
                                v84 = -2035858301;
                                break;
                            case 0xB5549AE6:
                                v84 = 1758832883;
                                v191 = (unsigned int)(-1024615602 * v180 + 296495529);
                                goto LABEL_523;
                            case 0xCE425D19:
                                v84 = -906019179;
                                v191 = (unsigned int)(-1281808950 * v191 + 259515109);
                                v85 = __ROR8__(v180, 32);
                            LABEL_524:
                                v180 = v85;
                                break;
                            }
                        }
                        else
                        {
                            switch (v83)
                            {
                            case 0x74E12C3Cu:
                                v84 = 243454834;
                                v191 = (unsigned int)(200042978 * v191 - 1747825582);
                                break;
                            case 0x1D0A97B8u:
                                v84 = 818544236;
                                goto LABEL_523;
                            case 0x44E91D50u:
                                v180 ^= v191;
                                v84 = 41647497;
                                break;
                            case 0x469260D9u:
                                v191 = (unsigned int)v180;
                                v84 = 846417125;
                                break;
                            case 0x665E9BDAu:
                                v191 = (unsigned int)v180;
                                v84 = 188262639;
                                break;
                            case 0x6D663335u:
                                v84 = 697249381;
                                v191 = (unsigned int)(-1027100199 * v191 - 1169118301);
                            LABEL_523:
                                v85 = __ROL8__(v180, 32);
                                goto LABEL_524;
                            }
                        }
                        v83 ^= v84;
                        if (v83 == 767781332)
                            goto LABEL_662;
                    }
                case 9LL:
                    v86 = 17228102;
                    v87 = -249265863;
                    do
                    {
                        if (v86 > 0x3FA6F923)
                        {
                            switch (v86)
                            {
                            case 0x41E6E0CDu:
                                v88 = __ROR8__(v180, 32);
                                v180 = v88 ^ v191;
                                v191 = (unsigned int)v88 ^ (unsigned int)v191;
                                v87 = 182089782;
                                break;
                            case 0x42D46A2Bu:
                                v87 = 12159089;
                                v191 = (unsigned int)(543337797 * v191 + 99077966);
                                v180 = __ROL8__(v180, 32);
                                break;
                            case 0x4B3C98FBu:
                                v191 = (unsigned int)(624902841 * v191 + 1941533838);
                                v180 = __ROR8__(v180, 32) ^ v191;
                                v87 = 1956274648;
                                break;
                            }
                        }
                        else
                        {
                            switch (v86)
                            {
                            case 0x3FA6F923u:
                                v87 = -879648540;
                                v180 = __ROR8__(v180, 32);
                                break;
                            case 0x106E146u:
                                v191 = (unsigned int)v180;
                                v87 = 151102642;
                                break;
                            case 0x56DD11Au:
                                v87 = 53627861;
                                v191 = (unsigned int)(1185796627 * v191 + 1685101042);
                                v180 = __ROL8__(v180, 32);
                                break;
                            case 0x80745F4u:
                                v87 = 1239524665;
                                v191 = (unsigned int)(-2023442180 * v191 + 1728003047);
                                break;
                            }
                        }
                        v86 ^= v87;
                    } while (v86 != -197699129);
                    goto LABEL_662;
                case 10LL:
                    v89 = 202225819;
                    v90 = 1300419157;
                   
                    while (1)
                    {
                        if (v89 <= 0x41DC5060)
                        {
                            switch (v89)
                            {
                            case 0x41DC5060u:
                                v90 = -1831061568;
                                v191 = (unsigned int)(1971854963 * v180 + 208503058);
                                v180 = __ROR8__(v180, 32);
                                break;
                            case 0xC0DB89Bu:
                                v191 = (unsigned int)v180;
                                v90 = -1193887241;
                                break;
                            case 0x3A9E2EF5u:
                                v90 = 189528517;
                                v180 = __ROL8__(v180 ^ v191, 32);
                                break;
                            case 0x3DE07379u:
                                v90 = 125721996;
                                v180 = __ROL8__(v180, 32);
                                break;
                            }
                            goto LABEL_563;
                        }
                        if (v89 == -1260715668)
                            break;
                        if (v89 == -378968943)
                        {
                            v90 = -1583791287;
                            v191 = (unsigned int)(2118936861 * v180 + 8794305);
                            v180 = __ROR8__(v180, 32);
                        }
                        else if (v89 == -375618103)
                        {
                            v91 = __ROR8__(v180, 32);
                            v180 = v91 ^ v191;
                            v90 = -730007888;
                            v92 = -870922274 * (v91 ^ v191) - 1350869549;
                        LABEL_562:
                            v191 = v92;
                        }
                    LABEL_563:
                        v89 ^= v90;
                        if (v89 == 836097840)
                            goto LABEL_662;
                    }
                    v90 = 1564968101;
                    v92 = 211664774 * v191 + 125944150;
                    goto LABEL_562;
                case 11LL:
                    v93 = -1768307420;
                    v94 = -2119073988;
                  
                    do
                    {
                        if (v93 > 0x67D5A434)
                        {
                            switch (v93)
                            {
                            case 0x966FE13B:
                                v191 = (unsigned int)(721143196 * v191 - 1849447714);
                                v180 = __ROR8__(v180, 32) ^ v191;
                                v94 = -1048597473;
                                break;
                            case 0x9699C524:
                                v191 = (unsigned int)v180;
                                v94 = 16131103;
                                break;
                            case 0xC9BE65DA:
                                v94 = -632544481;
                                v191 = (unsigned int)(-683282584 * v191 + 211406066);
                                break;
                            case 0xF2422DCC:
                                v94 = 356723530;
                                v191 = (unsigned int)(-109282174 * v180 + 1225834877);
                                break;
                            }
                        }
                        else
                        {
                            switch (v93)
                            {
                            case 0x67D5A434u:
                                v94 = -1755231590;
                                v180 = __ROR8__(v180, 32);
                                break;
                            case 0x83871CCu:
                                v94 = 465768817;
                                v191 = (unsigned int)(224663189 * v180 - 2079105806);
                                v180 = __ROL8__(v180, 32);
                                break;
                            case 0x13F246C5u:
                                v94 = 136068510;
                                v180 = __ROR8__(v180, 32);
                                break;
                            case 0x1BEE7B5Bu:
                                v180 ^= v191;
                                v94 = 2084298607;
                                break;
                            case 0x57104D24u:
                                v191 = (unsigned int)v180;
                                v94 = -1632753410;
                                break;
                            }
                        }
                        v93 ^= v94;
                    } while (v93 != -256577874);
                    goto LABEL_662;
                case 12LL:
                    v95 = 133975736;
                    v96 = 54222133;
                    while (1)
                    {
                        if (v95 > 0x16E891D5)
                        {
                            switch (v95)
                            {
                            case 0xB9C71A66:
                                v96 = -1232805481;
                                goto LABEL_604;
                            case 0xC06D1463:
                                v96 = -1154965631;
                                v191 = (unsigned int)(484521004 * v180 + 121461922);
                                v97 = __ROL8__(v180, 32);
                                goto LABEL_605;
                            case 0xC9F1FFCE:
                                v96 = -73393955;
                                v191 = (unsigned int)(172442944 * v191 + 38279832);
                                goto LABEL_604;
                            }
                        }
                        else
                        {
                            if (v95 != 384340437)
                            {
                                if (v95 == 130558006)
                                {
                                    v96 = 773307290;
                                    v97 = __ROL8__(v180, 32);
                                LABEL_605:
                                    v180 = v97;
                                    goto LABEL_606;
                                }
                                if (v95 != 133975736)
                                {
                                    if (v95 == 256113649)
                                    {
                                        v180 ^= v191;
                                        v96 = 143381447;
                                    }
                                    goto LABEL_606;
                                }
                                v96 = 286580589;
                                v191 = (unsigned int)(-626502888 * v180 - 1420822800);
                            LABEL_604:
                                v97 = __ROR8__(v180, 32);
                                goto LABEL_605;
                            }
                            v180 ^= v191;
                            v96 = -1355838541;
                            v191 = (unsigned int)(795388103 * v180 + 776203596);
                        }
                    LABEL_606:
                        v95 ^= v96;
                        if (v95 == 702518188)
                            goto LABEL_662;
                    }
                case 13LL:
                    v98 = 1882838193;
                    v99 = -1348543445;
                    
                    while (v98 != 1882838193)
                    {
                        switch (v98)
                        {
                        case -2039662633:
                            v99 = -1944126139;
                            v101 = -733090158 * v191 - 1227855031;
                        LABEL_618:
                            v191 = v101;
                            goto LABEL_619;
                        case -1871538530:
                            v180 ^= v191;
                            v99 = -1420222351;
                        LABEL_619:
                            v100 = __ROR8__(v180, 32);
                            goto LABEL_620;
                        case -960752779:
                            v99 = 283456969;
                            v191 = (unsigned int)(98005388 * v180 - 1970165435);
                            v100 = __ROL8__(v180, 32);
                        LABEL_620:
                            v180 = v100;
                            break;
                        }
                        v98 ^= v99;
                        if (v98 == 992720623)
                            goto LABEL_662;
                    }
                    v192 = (unsigned int)(-1135922884 * v180 - 2103950397);
                    v102 = __ROR8__(v180, 32);
                    v180 = v102 ^ v192;
                    v99 = -531938769;
                    v101 = 227627674 * (v102 ^ v192) - 629754947;
                    goto LABEL_618;
                case 14LL:
                    v103 = 345168306;
                    v104 = 178183464;
                    break;
                default:
                    v105 = 177632865;
                    v106 = 36603113;
                  
                    do
                    {
                        if (v105 > 0x50326C4D)
                        {
                            switch (v105)
                            {
                            case 0x8B4D5AD1:
                                v191 = (unsigned int)(-324428558 * v191 - 219778310);
                                v180 = __ROL8__(v180, 32) ^ v191;
                                v106 = 659484767;
                                break;
                            case 0x9314FA98:
                                v106 = 170578607;
                                v180 = __ROL8__(v180, 32);
                                break;
                            case 0xAC03AA8E:
                                v191 = v180 & 0xFFFFFFFF;
                                v106 = -1111822857;
                                break;
                            }
                        }
                        else
                        {
                            switch (v105)
                            {
                            case 0x50326C4Du:
                                v106 = 47612668;
                                v191 = (776855431 * v191 + 186010950) & 0xFFFFFFFF;
                                break;
                            case 0x3FFFAB2u:
                                v106 = 1388262361;
                                v191 = (-418174043 * v180 - 1065259190) & 0xFFFFFFFF;
                                v180 = __ROL8__(v180, 32);
                                break;
                            case 0xA967661u:
                                v191 = v180 & 0xFFFFFFFF;
                                v106 = -2116342608;
                                break;
                            case 0x11B94779u:
                                v191 = (unsigned int)(-802501250 * v191 + 447197752);
                                v180 = __ROR8__(v180, 32) ^ v191;
                                v106 = -2102542879;
                                break;
                            }
                        }
                        v105 ^= v106;
                    } while (v105 != -1723979721);
                    goto LABEL_662;
                }
                do
                {
                    if (v103 > 0x9D46AF22)
                    {
                        switch (v103)
                        {
                        case 0xBA7C8D18:
                            v104 = -333411105;
                            goto LABEL_641;
                        case 0xBB9C358E:
                            v180 ^= v191;
                            v104 = 31504534;
                            break;
                        case 0xFECC9736:
                            v104 = -256044548;
                            goto LABEL_641;
                        }
                    }
                    else
                    {
                        if (v103 == -1656312030)
                        {
                            v104 = -141878668;
                            v191 = (unsigned int)(670213550 * v191 - 1986870942);
                            goto LABEL_641;
                        }
                        if (v103 == 242321098)
                        {
                            v180 ^= v191;
                            v104 = -1242713276;
                            v191 = (unsigned int)(1698697915 * v180 - 1084105573);
                        LABEL_641:
                            v180 = __ROL8__(v180, 32);
                            goto LABEL_642;
                        }
                        if (v103 != 345168306)
                        {
                            if (v103 != 1687367221)
                            {
                                if (v103 == -1728105729)
                                {
                                    v104 = 1714660809;
                                    v191 = (unsigned int)(-1590201873 * v191 - 717221051);
                                }
                                goto LABEL_642;
                            }
                            v104 = 1605191868;
                            v191 = (unsigned int)(350900435 * v180 + 1229439886);
                            goto LABEL_641;
                        }
                        v191 = (unsigned int)v180;
                        v104 = -1938953395;
                    }
                LABEL_642:
                    v103 ^= v104;
                } while (v103 != 1448870343);
            }
        LABEL_662:
            v59 = v180 + 2304LL * 0; //v1
            return v59;
        LABEL_663:
            ++v1;
            BYTE newValue = a1;
            WriteProcessMemory(hProcess, (LPVOID)(v59 + 2), &newValue, sizeof(newValue), nullptr);
           // *(BYTE*)(v59 + 2) = a1;
        }
        while (v1 < 1024);
        v182 = *(uint64_t*)(8LL * a1 + 80837472);
        if (v182)
        {
            v107 = GetSwitchCaseValue(hProcess);
            v193 = v107;
            switch (v107)
            {
            case 0u:
                v108 = 823565520;
             
                v109 = 492343627;
                do
                {
                    switch (v108)
                    {
                    case 38577259:
                        v193 = (1296735014 * v193 + 137285340) & 0xFFFFFFFF;
                        v182 = __ROR8__(v182, 32);
                        v109 = 80958019;
                        break;
                    case 823565520:
                        v109 = 7461030;
                        v182 = __ROR8__(v182, 32) ^ (unsigned int)(-141319033 * v182 - 1690604579);
                        v193 = v182 & 0xFFFFFFFF;
                        break;
                    case 828851318:
                        v193 = (unsigned int)(88756900 * v193 + 933478499);
                        v182 = __ROR8__(__ROR8__(v182, 32) ^ v193, 32);
                        v109 = 126806196;
                        break;
                    case -1129975960:
                        v193 = (215051184 * v193 + 2010730492) & 0xFFFFFFFF;
                        v109 = -121464852;
                        break;
                    }
                    v108 ^= v109;
                } while (v108 != 921283778);
                goto LABEL_703;
            case 1u:
                v110 = -1975998875;
             
                v111 = 1448921146;
                do
                {
                    if (v110 > 0x2B7C6A9D)
                    {
                        switch (v110)
                        {
                        case 0x712D039Bu:
                            v111 = 1818635335;
                            v193 = (unsigned int)v182;
                            break;
                        case 0x7E41E8E8u:
                            v111 = 258796403;
                            v182 = __ROL8__(v182, 32) ^ v193;
                            break;
                        case 0x8A38A665:
                            v193 = (unsigned int)(-472157018 * v182 - 90928863);
                            v111 = -193376627;
                            break;
                        }
                    }
                    else
                    {
                        switch (v110)
                        {
                        case 0x2B7C6A9Du:
                            v182 = __ROL8__(__ROL8__(v182, 32) ^ v193, 32);
                            v111 = -2131911400;
                            break;
                        case 0xAD67477u:
                            v193 = (unsigned int)(-764692141 * v193 - 994843541);
                            v182 = __ROL8__(v182, 32);
                            v111 = -1423722364;
                            break;
                        case 0xF8BADB0u:
                            v193 = (unsigned int)(14087958 * v182 + 1700830413);
                            v111 = 728542159;
                            break;
                        case 0x1D4B2FDCu:
                            v193 = (unsigned int)(-356675895 * v193 - 802358677);
                            v111 = 909591873;
                            break;
                        }
                    }
                    v110 ^= v111;
                } while (v110 != -1416497275);
                goto LABEL_703;
            case 2u:
                v113 = -1361814192;
               
                while (1)
                {
                    if (v113 > 0x84DBABD0)
                    {
                        if (v113 == -1361814192)
                        {
                            v3 = -1775290211;
                        }
                        else
                        {
                            if (v113 != -1338373062)
                            {
                                if (v113 == -1323249115)
                                {
                                    v3 = 18538015;
                                    v182 = __ROL8__(v182, 32) ^ v193;
                                }
                                else if (v113 == -842837720)
                                {
                                    v3 = -1270798377;
                                    v193 = (unsigned int)(1284189861 * v182 - 1409726422);
                                    v182 = __ROL8__(v182, 32);
                                }
                                goto LABEL_727;
                            }
                            v3 = -288387487;
                        }
                        v193 = (unsigned int)v182;
                    }
                    else
                    {
                        switch (v113)
                        {
                        case 0x84DBABD0:
                            v3 = 658807013;
                            v193 = (unsigned int)(-1438266349 * v193 + 1794694572);
                            v182 = __ROR8__(v182, 32);
                            break;
                        case 0x38FB65CDu:
                            v3 = -1982089240;
                            v193 = (unsigned int)(-439572449 * v193 + 1814227452);
                            break;
                        case 0x50E25019u:
                            v3 = 766386737;
                            v182 = __ROR8__(v182, 32) ^ v193;
                            break;
                        case 0x5EF5825Bu:
                            v3 = 236442178;
                            v193 = (unsigned int)(841589274 * v193 + 1351544006);
                            break;
                        case 0x7D4C7228u:
                            v3 = 1101440479;
                            v182 = __ROL8__(v182, 32);
                            break;
                        }
                    }
                LABEL_727:
                    v113 ^= v3;
                    if (v113 == 1022023671)
                        goto LABEL_703;
                }
            case 3u:
                v114 = -1944470796;
             
                v115 = 9317208;
                do
                {
                    if (v114 > 0xF24DE9D6)
                    {
                        if (v114 == -218064983)
                        {
                            v184 = v182 ^ v193;
                            v193 = (unsigned int)(1002419580 * v184 - 549351579);
                            v182 = __ROL8__(v184, 32);
                            v115 = 21855871;
                        }
                        else if (v114 == -88769625)
                        {
                            v193 = (unsigned int)(-1798807866 * v182 + 1593419556);
                            v182 = __ROL8__(v182, 32);
                            v115 = 963112816;
                        }
                    }
                    else
                    {
                        switch (v114)
                        {
                        case 0xF24DE9D6:
                            v115 = 1396241585;
                            v182 ^= v193;
                            break;
                        case 0x1B173DEu:
                            v193 = (unsigned int)(-1175823308 * v193 + 901089883);
                            v182 = __ROR8__(v182, 32);
                            v115 = 1700940229;
                            break;
                        case 0x8C19BAF4:
                            v193 = (unsigned int)(-316254171 * v182 - 1208235235);
                            v182 = __ROL8__(v182, 32);
                            v115 = 2132356445;
                            break;
                        case 0xA1751D67:
                            v182 = __ROL8__(v182, 32);
                            v115 = 81942235;
                            break;
                        }
                    }
                    v114 ^= v115;
                } while (v114 != -1516811332);
                goto LABEL_703;
            case 4u:
                v116 = 162721395;
         
                v117 = -360128163;
                do
                {
                    if (v116 > 0x871BB870)
                    {
                        if (v116 == -512288553)
                        {
                            v117 = 1718395047;
                            v193 = (unsigned int)v182;
                        }
                        else if (v116 == -422977131)
                        {
                            v182 = __ROR8__(v182 ^ v193, 32);
                            v117 = -1395706215;
                        }
                    }
                    else
                    {
                        switch (v116)
                        {
                        case 0x871BB870:
                            v193 = (unsigned int)(-615647428 * v193 + 185931929);
                            v182 = __ROL8__(v182, 32);
                            v117 = 1641175525;
                            break;
                        case 0x9B2EE73u:
                            v193 = (unsigned int)(132586473 * v182 + 1099275482);
                            v117 = -389679452;
                            v182 = __ROL8__(v182, 32) ^ v193;
                            break;
                        case 0x14BCEB56u:
                            v193 = (unsigned int)(1876423119 * v193 + 2012692203);
                            v117 = 180913272;
                            break;
                        case 0x515633C2u:
                            v193 = (unsigned int)(1991054030 * v193 + 1231923379);
                            v182 = __ROL8__(v182, 32);
                            v117 = 1950463062;
                            break;
                        }
                    }
                    v116 ^= v117;
                } while (v116 != 1241962252);
                goto LABEL_703;
            case 5u:
                v118 = -1946901737;
        
                while (1)
                {
                    if (v118 > 0xA4207E17)
                    {
                        switch (v118)
                        {
                        case 0xA6E75E8D:
                            v2 = 1114489935;
                            v120 = 69775203 * v182 - 1438590907;
                            goto LABEL_794;
                        case 0xB9E8FC70:
                            v2 = 108396383;
                            v193 = (unsigned int)(209498205 * v193 - 958401484);
                            break;
                        case 0xBF9D032F:
                            v2 = -2109729862;
                            v119 = __ROR8__(v182, 32);
                            goto LABEL_795;
                        }
                    }
                    else
                    {
                        switch (v118)
                        {
                        case 0xA4207E17:
                            v2 = 83589932;
                            v120 = -1898427702 * v193 - 1713071270;
                        LABEL_794:
                            v193 = v120;
                            v119 = __ROL8__(v182, 32);
                            goto LABEL_795;
                        case 0x3DDD1095u:
                            v2 = -1353038126;
                            v119 = __ROR8__(v182 ^ v193, 32);
                            goto LABEL_795;
                        case 0x4686FED6u:
                            v2 = 601404411;
                            v182 ^= v193;
                            break;
                        case 0x655E4D2Du:
                            v2 = -592006819;
                            v193 = (unsigned int)v182;
                            break;
                        case 0x8BF4A317:
                            v2 = -848142911;
                            v193 = (unsigned int)(-576055819 * v182 - 1585184923);
                            v119 = __ROR8__(v182, 32);
                        LABEL_795:
                            v182 = v119;
                            break;
                        }
                    }
                    v118 ^= v2;
                    if (v118 == -1836624313)
                        goto LABEL_703;
                }
            case 6u:
                v121 = 1406735124;
            
                v122 = -1787769859;
                do
                {
                    if (v121 > 0x6B11C26E)
                    {
                        if (v121 == -699210272)
                        {
                            v193 = (unsigned int)(44416355 * v193 - 1162335614);
                            v122 = -348079699;
                        }
                        else if (v121 == -232483533)
                        {
                            v123 = __ROR8__(v182, 32);
                            v185 = v123 ^ v193;
                            v193 = 268299812 * ((unsigned int)v123 ^ (unsigned int)v193) + 1986535518;
                            v122 = -55566135;
                            v182 = __ROL8__(v185, 32) ^ v193;
                        }
                    }
                    else
                    {
                        switch (v121)
                        {
                        case 0x6B11C26Eu:
                            v193 = (unsigned int)(-2047960159 * v193 - 1972334193);
                            v122 = -1724557475;
                            break;
                        case 0x589DB47u:
                            v193 = (unsigned int)(10950705 * v182 + 199910170);
                            v182 = __ROR8__(v182, 32);
                            v122 = -296583035;
                            break;
                        case 0xE94B5FAu:
                            v182 = __ROR8__(v182, 32);
                            v122 = -265011713;
                            break;
                        case 0x53D91314u:
                            v122 = 952684922;
                            v193 = (unsigned int)v182;
                            break;
                        }
                    }
                    v121 ^= v122;
                } while (v121 != -23033851);
                goto LABEL_703;
            case 7u:
                v124 = 12007180;
               
                do
                {
                    if (v124 > 0x72A9E1D0)
                    {
                        switch (v124)
                        {
                        case 0x77CD3B38u:
                            v5 = 131732506;
                            v182 = __ROR8__(v182, 32) ^ v193;
                            break;
                        case 0xBC711283:
                            v5 = 607485615;
                            v193 = (unsigned int)(-619400760 * v193 + 205257232);
                            break;
                        case 0xDEC92A47:
                            v5 = 178160935;
                            v182 = __ROR8__(v182 ^ v193, 32);
                            break;
                        }
                    }
                    else
                    {
                        switch (v124)
                        {
                        case 0x72A9E1D0u:
                            v5 = -1402942569;
                            v182 = __ROR8__(v182, 32);
                            break;
                        case 0xB7370Cu:
                            v5 = 1126968726;
                            v193 = (unsigned int)v182;
                            break;
                        case 0xFE71322u:
                            v5 = -1516221267;
                            v193 = (unsigned int)(1002951918 * v182 - 1779596728);
                            v182 = __ROR8__(v182, 32);
                            break;
                        case 0x439B1A9Au:
                            v5 = 878059938;
                            v193 = (unsigned int)(976014953 * v193 + 1440717871);
                            break;
                        case 0x70172F22u:
                            v5 = 46059250;
                            v193 = (unsigned int)(-26951093 * v182 + 267301935);
                            break;
                        }
                    }
                    v124 ^= v5;
                } while (v124 != -732450976);
                goto LABEL_703;
            case 8u:
                v125 = 1717476314;
                while (1)
                {
                    if (v125 > 0x74E12C3C)
                    {
                        switch (v125)
                        {
                        case 0x7A63FF4Eu:
                            v6 = -506581899;
                            goto LABEL_864;
                        case 0x9BADD33B:
                            v6 = -2035858301;
                            v182 ^= v193;
                            break;
                        case 0xB5549AE6:
                            v6 = 1758832883;
                            v193 = (unsigned int)(-1024615602 * v182 + 296495529);
                            goto LABEL_864;
                        case 0xCE425D19:
                            v6 = -906019179;
                            v193 = (unsigned int)(-1281808950 * v193 + 259515109);
                            v126 = __ROR8__(v182, 32);
                        LABEL_865:
                            v182 = v126;
                            break;
                        }
                    }
                    else
                    {
                        switch (v125)
                        {
                        case 0x74E12C3Cu:
                            v6 = 243454834;
                            v193 = (unsigned int)(200042978 * v193 - 1747825582);
                            break;
                        case 0x1D0A97B8u:
                            v6 = 818544236;
                            goto LABEL_864;
                        case 0x44E91D50u:
                            v6 = 41647497;
                            v182 ^= v193;
                            break;
                        case 0x469260D9u:
                            v6 = 846417125;
                            v193 = (unsigned int)v182;
                            break;
                        case 0x665E9BDAu:
                            v6 = 188262639;
                            v193 = (unsigned int)v182;
                            break;
                        case 0x6D663335u:
                            v6 = 697249381;
                            v193 = (unsigned int)(-1027100199 * v193 - 1169118301);
                        LABEL_864:
                            v126 = __ROL8__(v182, 32);
                            goto LABEL_865;
                        }
                    }
                    v125 ^= v6;
                    if (v125 == 767781332)
                        goto LABEL_703;
                }
            case 9u:
                v127 = 17228102;
                while (v127 <= 0x3FA6F923)
                {
                    if (v127 != 1067907363)
                    {
                        if (v127 != 17228102)
                        {
                            if (v127 == 91083034)
                            {
                                v7 = 53627861;
                                v193 = (unsigned int)(1185796627 * v193 + 1685101042);
                                v182 = __ROL8__(v182, 32);
                            }
                            else if (v127 == 134694388)
                            {
                                v7 = 1239524665;
                                v193 = (unsigned int)(-2023442180 * v193 + 1728003047);
                            }
                            goto LABEL_885;
                        }
                        v7 = 151102642;
                        goto LABEL_884;
                    }
                    v7 = -879648540;
                    v182 = __ROR8__(v182, 32);
                LABEL_885:
                    v127 ^= v7;
                    if (v127 == -197699129)
                        goto LABEL_703;
                }
                if (v127 != 1105649869)
                {
                    if (v127 == 1121217067)
                    {
                        v7 = 12159089;
                        v193 = (unsigned int)(543337797 * v193 + 99077966);
                        v182 = __ROL8__(v182, 32);
                    }
                    else if (v127 == 1262262523)
                    {
                        v7 = 1956274648;
                        v193 = (unsigned int)(624902841 * v193 + 1941533838);
                        v182 = __ROR8__(v182, 32) ^ v193;
                    }
                    goto LABEL_885;
                }
                v7 = 182089782;
                v182 = __ROR8__(v182, 32) ^ v193;
            LABEL_884:
                v193 = (unsigned int)v182;
                goto LABEL_885;
            case 0xAu:
                v128 = 202225819;
               
                while (1)
                {
                    if (v128 <= 0x41DC5060)
                    {
                        switch (v128)
                        {
                        case 0x41DC5060u:
                            v8 = -1831061568;
                            v193 = (unsigned int)(1971854963 * v182 + 208503058);
                            v182 = __ROR8__(v182, 32);
                            break;
                        case 0xC0DB89Bu:
                            v8 = -1193887241;
                            v193 = (unsigned int)v182;
                            break;
                        case 0x3A9E2EF5u:
                            v8 = 189528517;
                            v182 = __ROL8__(v182 ^ v193, 32);
                            break;
                        case 0x3DE07379u:
                            v8 = 125721996;
                            v182 = __ROL8__(v182, 32);
                            break;
                        }
                        goto LABEL_905;
                    }
                    if (v128 == -1260715668)
                        break;
                    if (v128 == -378968943)
                    {
                        v8 = -1583791287;
                        v193 = (unsigned int)(2118936861 * v182 + 8794305);
                        v182 = __ROR8__(v182, 32);
                    }
                    else if (v128 == -375618103)
                    {
                        v8 = -730007888;
                        v129 = __ROR8__(v182, 32);
                        v182 = v129 ^ v193;
                        v130 = -870922274 * (v129 ^ v193) - 1350869549;
                    LABEL_904:
                        v193 = v130;
                    }
                LABEL_905:
                    v128 ^= v8;
                    if (v128 == 836097840)
                        goto LABEL_703;
                }
                v8 = 1564968101;
                v130 = 211664774 * v193 + 125944150;
                goto LABEL_904;
            case 0xBu:
                v131 = -1768307420;
              
                while (v131 <= 0x67D5A434)
                {
                    if (v131 == 1742054452)
                    {
                        v9 = -1755231590;
                        v182 = __ROR8__(v182, 32);
                    }
                    else if (v131 == 137916876)
                    {
                        v9 = 465768817;
                        v193 = (unsigned int)(224663189 * v182 - 2079105806);
                        v182 = __ROL8__(v182, 32);
                    }
                    else
                    {
                        if (v131 != 334644933)
                        {
                            if (v131 != 468613979)
                            {
                                if (v131 == 1460686116)
                                {
                                    v9 = -1632753410;
                                    v193 = (unsigned int)v182;
                                }
                                goto LABEL_929;
                            }
                            v9 = 2084298607;
                            goto LABEL_928;
                        }
                        v9 = 136068510;
                        v182 = __ROR8__(v182, 32);
                    }
                LABEL_929:
                    v131 ^= v9;
                    if (v131 == -256577874)
                        goto LABEL_703;
                }
                if (v131 != -1771052741)
                {
                    switch (v131)
                    {
                    case 0x9699C524:
                        v9 = 16131103;
                        v193 = (unsigned int)v182;
                        break;
                    case 0xC9BE65DA:
                        v9 = -632544481;
                        v193 = (unsigned int)(-683282584 * v193 + 211406066);
                        break;
                    case 0xF2422DCC:
                        v9 = 356723530;
                        v193 = (unsigned int)(-109282174 * v182 + 1225834877);
                        break;
                    }
                    goto LABEL_929;
                }
                v9 = -1048597473;
                v193 = (unsigned int)(721143196 * v193 - 1849447714);
                v182 = __ROR8__(v182, 32);
            LABEL_928:
                v182 ^= v193;
                goto LABEL_929;
            case 0xCu:
                v132 = 133975736;
                while (1)
                {
                    if (v132 > 0x16E891D5)
                    {
                        switch (v132)
                        {
                        case 0xB9C71A66:
                            v10 = -1232805481;
                            goto LABEL_947;
                        case 0xC06D1463:
                            v10 = -1154965631;
                            v193 = (unsigned int)(484521004 * v182 + 121461922);
                            v133 = __ROL8__(v182, 32);
                            goto LABEL_948;
                        case 0xC9F1FFCE:
                            v10 = -73393955;
                            v193 = (unsigned int)(172442944 * v193 + 38279832);
                            goto LABEL_947;
                        }
                    }
                    else
                    {
                        if (v132 != 384340437)
                        {
                            if (v132 == 130558006)
                            {
                                v10 = 773307290;
                                v133 = __ROL8__(v182, 32);
                            LABEL_948:
                                v182 = v133;
                                goto LABEL_949;
                            }
                            if (v132 != 133975736)
                            {
                                if (v132 == 256113649)
                                {
                                    v10 = 143381447;
                                    v182 ^= v193;
                                }
                                goto LABEL_949;
                            }
                            v10 = 286580589;
                            v193 = (unsigned int)(-626502888 * v182 - 1420822800);
                        LABEL_947:
                            v133 = __ROR8__(v182, 32);
                            goto LABEL_948;
                        }
                        v10 = -1355838541;
                        v182 ^= v193;
                        v193 = (unsigned int)(795388103 * v182 + 776203596);
                    }
                LABEL_949:
                    v132 ^= v10;
                    if (v132 == 702518188)
                        goto LABEL_703;
                }
            case 0xDu:
                v134 = 1882838193;
         
                v135 = -1348543445;
                do
                {
                    switch (v134)
                    {
                    case 1882838193:
                        v195 = (unsigned int)(-1135922884 * v182 - 2103950397);
                        v136 = __ROR8__(v182, 32);
                        v186 = v136 ^ v195;
                        v193 = 227627674 * ((unsigned int)v136 ^ (unsigned int)v195) - 629754947;
                        v182 = __ROR8__(v186, 32);
                        v135 = -531938769;
                        break;
                    case -2039662633:
                        v193 = (unsigned int)(-733090158 * v193 - 1227855031);
                        v182 = __ROR8__(v182, 32);
                        v135 = -1944126139;
                        break;
                    case -1871538530:
                        v182 = __ROR8__(v182 ^ v193, 32);
                        v135 = -1420222351;
                        break;
                    case -960752779:
                        v193 = (unsigned int)(98005388 * v182 - 1970165435);
                        v182 = __ROL8__(v182, 32);
                        v135 = 283456969;
                        break;
                    }
                    v134 ^= v135;
                } while (v134 != 992720623);
                goto LABEL_703;
            case 0xEu:
                v137 = 345168306;
                while (1)
                {
                    if (v137 > 0x9D46AF22)
                    {
                        switch (v137)
                        {
                        case 0xBA7C8D18:
                            v4 = -333411105;
                            goto LABEL_982;
                        case 0xBB9C358E:
                            v4 = 31504534;
                            v182 ^= v193;
                            break;
                        case 0xFECC9736:
                            v4 = -256044548;
                            goto LABEL_982;
                        }
                    }
                    else
                    {
                        if (v137 == -1656312030)
                        {
                            v4 = -141878668;
                            v193 = (unsigned int)(670213550 * v193 - 1986870942);
                            goto LABEL_982;
                        }
                        if (v137 == 242321098)
                        {
                            v4 = -1242713276;
                            v182 ^= v193;
                            v193 = (unsigned int)(1698697915 * v182 - 1084105573);
                        LABEL_982:
                            v182 = __ROL8__(v182, 32);
                            goto LABEL_983;
                        }
                        if (v137 != 345168306)
                        {
                            if (v137 != 1687367221)
                            {
                                if (v137 == -1728105729)
                                {
                                    v4 = 1714660809;
                                    v193 = (unsigned int)(-1590201873 * v193 - 717221051);
                                }
                                goto LABEL_983;
                            }
                            v4 = 1605191868;
                            v193 = (unsigned int)(350900435 * v182 + 1229439886);
                            goto LABEL_982;
                        }
                        v4 = -1938953395;
                        v193 = (unsigned int)v182;
                    }
                LABEL_983:
                    v137 ^= v4;
                    if (v137 == 1448870343)
                        goto LABEL_703;
                }
            default:
                v138 = 177632865;
            
                break;
            }
            while (2)
            {
                if (v138 > 0x50326C4D)
                {
                    switch (v138)
                    {
                    case 0x8B4D5AD1:
                        v11 = 659484767;
                        v193 = (unsigned int)(-324428558 * v193 - 219778310);
                        v139 = __ROL8__(v182, 32);
                    LABEL_1002:
                        v182 = v139 ^ v193;
                        break;
                    case 0x9314FA98:
                        v11 = 170578607;
                        v182 = __ROL8__(v182, 32);
                        break;
                    case 0xAC03AA8E:
                        v11 = -1111822857;
                        v193 = v182 & 0xFFFFFFFF;
                        break;
                    }
                }
                else
                {
                    switch (v138)
                    {
                    case 0x50326C4Du:
                        v11 = 47612668;
                        v193 = (776855431 * v193 + 186010950) & 0xFFFFFFFF;
                        break;
                    case 0x3FFFAB2u:
                        v11 = 1388262361;
                        v193 = (-418174043 * v182 - 1065259190) & 0xFFFFFFFF;
                        v182 = __ROL8__(v182, 32);
                        break;
                    case 0xA967661u:
                        v11 = -2116342608;
                        v193 = v182 & 0xFFFFFFFF;
                        break;
                    case 0x11B94779u:
                        v11 = -2102542879;
                        v193 = (unsigned int)(-802501250 * v193 + 447197752);
                        v139 = __ROR8__(v182, 32);
                        goto LABEL_1002;
                    }
                }
                v138 ^= v11;
                if (v138 == -1723979721)
                    break;
                continue;
            }
        }
    LABEL_703:
        memset((void*)(v182 + 2359296), 0, 0x1B0000uLL);
        v112 = (v112 & 0xFFFFFF00) | 1;
        //sub_105D150((unsigned int)a1, v112);
        v183 = enrypted_pointer_CG;
        if (enrypted_pointer_CG)
        {
            v194 = GetSwitchCaseValue(hProcess);
            switch (v194)
            {
            case 0LL:
                v140 = -182854066;
             
                v141 = -478971047;
                do
                {
                    if (v140 > 0x8DEB238F)
                    {
                        switch (v140)
                        {
                        case 0xF3B20C43:
                            v141 = 166269469;
                            v194 = (unsigned int)v183;
                            break;
                        case 0xF519DE4E:
                            v194 = (unsigned int)(1584075655 * v183 + 586718870);
                            v183 = __ROR8__(v183, 32);
                            v141 = -2020477958;
                            break;
                        case 0xFA5B1E5E:
                            v194 = (unsigned int)(791346458 * v194 + 394843719);
                            v141 = 1904166624;
                            break;
                        }
                    }
                    else
                    {
                        switch (v140)
                        {
                        case 0x8DEB238F:
                            v183 = __ROR8__(v183 ^ v194, 32);
                            v141 = 918184919;
                            break;
                        case 0xBED37BDu:
                            v194 = (unsigned int)(-1316252713 * v194 + 26433920);
                            v141 = 1325101890;
                            break;
                        case 0xE8C3FE5u:
                            v194 = (unsigned int)(2128931962 * v194 + 196012193);
                            v141 = 1231084083;
                            break;
                        case 0x72882DB4u:
                            v141 = -2126896649;
                            v183 ^= v194;
                            break;
                        case 0x8B2458BE:
                            v183 = __ROR8__(v183, 32);
                            v141 = 114260785;
                            break;
                        }
                    }
                    v140 ^= v141;
                } while (v140 != -1152303016);
                goto LABEL_1319;
            case 1LL:
                v142 = 660675447;
               
                v143 = -2053597133;
                do
                {
                    if (v142 > 0x66ADB428)
                    {
                        switch (v142)
                        {
                        case 0x6DE625ECu:
                            v183 = __ROL8__(v183, 32);
                            v143 = 95124402;
                            break;
                        case 0x8DC8A84C:
                            v194 = (unsigned int)(17937816 * v194 + 502857703);
                            v143 = 1397736980;
                            break;
                        case 0xDE876E58:
                            v183 = __ROR8__(v183, 32);
                            v143 = -1205151120;
                            break;
                        }
                    }
                    else
                    {
                        switch (v142)
                        {
                        case 0x66ADB428u:
                            v143 = 189501892;
                            v183 ^= v194;
                            break;
                        case 0xF94D68Eu:
                            v194 = (unsigned int)(-504650155 * v183 + 1738583875);
                            v183 = __ROR8__(v183, 32);
                            v143 = 545908193;
                            break;
                        case 0x27611B77u:
                            v143 = 204721257;
                            v194 = (unsigned int)v183;
                            break;
                        case 0x2B52D71Eu:
                            v143 = -1499824302;
                            v183 = __ROL8__(v183, 32) ^ (unsigned int)(-1807769420 * v194 - 597445928);
                            v194 = (unsigned int)v183;
                            break;
                        case 0x59258FECu:
                            v194 = (unsigned int)(1601909380 * v194 + 376262430);
                            v143 = 246496120;
                            break;
                        }
                    }
                    v142 ^= v143;
                } while (v142 != 1749900894);
                goto LABEL_1319;
            case 2LL:
                v144 = -491906180;
          
                v145 = -7224882;
                do
                {
                    switch (v144)
                    {
                    case 518440219:
                        v194 = (unsigned int)(691598882 * v183 - 563734325);
                        v183 = __ROL8__(__ROL8__(v183, 32) ^ v194, 32);
                        v145 = 226869046;
                        break;
                    case 1244810051:
                        v194 = (331326231 * v194 + 23673370) & 0xFFFFFFFF;
                        v145 = 259653529;
                        break;
                    case -1470550873:
                        v194 = (-1540283608 * v194 + 2010879009) & 0xFFFFFFFF;
                        v145 = 770117671;
                        break;
                    case -491906180:
                        v194 = (unsigned int)(119156141 * v183 - 770314270);
                        v145 = -62333337;
                        v183 = __ROR8__(v183, 32) ^ v194;
                        break;
                    }
                    v144 ^= v145;
                } while (v144 != 325286445);
                goto LABEL_1319;
            case 3LL:
                v146 = 617725989;
            
                v147 = -745725959;
                do
                {
                    if (v146 > 0x24D1C025)
                    {
                        switch (v146)
                        {
                        case 0x429B89C8u:
                            v194 = (unsigned int)(1766346885 * v194 - 1012174494);
                            v183 = __ROL8__(v183, 32);
                            v147 = 1094927146;
                            break;
                        case 0x644154CDu:
                            v194 = (unsigned int)(-830598076 * v194 - 1606521245);
                            v147 = 54483382;
                            break;
                        case 0x913A4E10:
                            v183 = __ROL8__(v183 ^ v194, 32);
                            v147 = 334970621;
                            break;
                        }
                    }
                    else
                    {
                        switch (v146)
                        {
                        case 0x24D1C025u:
                            v147 = 1716144621;
                            v194 = (unsigned int)v183;
                            break;
                        case 0x3D8CAE2u:
                            v147 = 179401950;
                            v183 ^= v194;
                            break;
                        case 0x862A67Bu:
                            v194 = (unsigned int)(116059748 * v183 + 1159974097);
                            v183 = __ROL8__(v183, 32);
                            v147 = 918497535;
                            break;
                        case 0x969BE3Cu:
                            v194 = (unsigned int)(1801497905 * v183 - 291203075);
                            v183 = __ROR8__(v183, 32);
                            v147 = -1739329492;
                            break;
                        }
                    }
                    v146 ^= v147;
                } while (v146 != -2100465427);
                goto LABEL_1319;
            case 4LL:
                v148 = 2135172155;
                v149 = 106430227;
                do
                {
                    if (v148 > 0x6EA8BAE8)
                    {
                        switch (v148)
                        {
                        case 0x7F44243Bu:
                            v194 = (unsigned int)(8765184 * v183 + 78628830);
                            v149 = -1939768772;
                            break;
                        case 0xC7D6F950:
                            v149 = -1069390290;
                            v194 = (unsigned int)v183;
                            break;
                        case 0xF3255E07:
                            v183 = __ROR8__(v183, 32);
                            v149 = -1596830739;
                            break;
                        }
                    }
                    else
                    {
                        switch (v148)
                        {
                        case 0x6EA8BAE8u:
                            v194 = (unsigned int)(-1346964338 * v194 + 1699332261);
                            v183 = __ROL8__(v183, 32);
                            v149 = 314332228;
                            break;
                        case 0x7949F7Eu:
                            v194 = (unsigned int)(-1888751842 * v194 - 1018856490);
                            v183 = __ROR8__(v183, 32);
                            v149 = 213399329;
                            break;
                        case 0xB2CA85Fu:
                            v183 = __ROL8__(v183 ^ v194, 32);
                            v149 = -1814052536;
                            break;
                        case 0x4AFF4D82u:
                            v194 = (unsigned int)(-1069554871 * v183 - 2001770735);
                            v183 = __ROR8__(v183, 32);
                            v149 = -1085569433;
                            break;
                        case 0x53F715EAu:
                            v149 = -1809716038;
                            v183 ^= v194;
                            break;
                        }
                    }
                    v148 ^= v149;
                } while (v148 != -1728878313);
                goto LABEL_1319;
            case 5LL:
                v150 = -1060124190;
                v151 = 661575635;
                do
                {
                    switch (v150)
                    {
                    case 267875343:
                        v194 = (unsigned int)(223128853 * v183 + 1755225231);
                        v151 = -889731599;
                        break;
                    case 271137405:
                        v183 = __ROL8__(v183, 32);
                        v151 = -1921003845;
                        break;
                    case -1655245626:
                        v183 = __ROL8__(v183 ^ v194, 32);
                        v151 = 95142508;
                        break;
                    case -1060124190:
                        v196 = (unsigned int)(132219338 * v183 - 2041947905);
                        v152 = __ROL8__(v183, 32);
                        v183 = v152 ^ v196;
                        v194 = -1143138413 * ((unsigned int)v152 ^ (unsigned int)v196) + 154192296;
                        v151 = -790170721;
                        break;
                    case -425404207:
                        v194 = (unsigned int)(1119826086 * v183 + 988991924);
                        v183 = __ROR8__(v183, 32);
                        v151 = 1503285818;
                        break;
                    }
                    v150 ^= v151;
                } while (v150 != -1728235862);
                goto LABEL_1319;
            case 6LL:
                v153 = 1895346683;
                v154 = 418947001;
                do
                {
                    if (v153 > 0x37DDC45A)
                    {
                        switch (v153)
                        {
                        case 0x70F8B1FBu:
                            v154 = 263328172;
                            v194 = (unsigned int)v183;
                            break;
                        case 0x7F4AA057u:
                            v194 = (unsigned int)(1807498829 * v194 + 1377314933);
                            v154 = 2145248564;
                            break;
                        case 0xA7ED7A40:
                            v183 = __ROR8__(v183 ^ v194, 32);
                            v154 = -1746790300;
                            break;
                        }
                    }
                    else
                    {
                        switch (v153)
                        {
                        case 0x37DDC45Au:
                            v194 = (unsigned int)(672918983 * v194 + 581323356);
                            v183 = __ROR8__(v183, 32);
                            v154 = 45580216;
                            break;
                        case 0x974563u:
                            v183 = __ROR8__(v183, 32);
                            v154 = 185448874;
                            break;
                        case 0xB9AFCC9u:
                            v154 = 581385833;
                            v183 ^= v194;
                            break;
                        case 0x293DC2A0u:
                            v194 = (unsigned int)(-731896304 * v183 + 121378778);
                            v183 = __ROL8__(v183, 32);
                            v154 = -1898923808;
                            break;
                        case 0x2B261838u:
                            v194 = (unsigned int)(-379229597 * v194 + 192823981);
                            v183 = __ROR8__(v183, 32);
                            v154 = 1406383041;
                            break;
                        }
                    }
                    v153 ^= v154;
                } while (v153 != 806314532);
                goto LABEL_1319;
            case 7LL:
                v155 = 230532316;
               
                v156 = -464864257;
                do
                {
                    if (v155 > 0x6B2BBBF2)
                    {
                        switch (v155)
                        {
                        case 0xB3F222FE:
                            v194 = (unsigned int)(-1840991455 * v183 + 544562082);
                            v156 = -266439830;
                            break;
                        case 0xB5195A86:
                            v156 = 1794880900;
                            v183 = __ROL8__(v183, 32) ^ v194;
                            break;
                        case 0xDFE2EF02:
                            v183 = __ROR8__(v183, 32);
                            v156 = 180212815;
                            break;
                        }
                    }
                    else
                    {
                        switch (v155)
                        {
                        case 0x6B2BBBF2u:
                            v194 = (unsigned int)(1888766672 * v194 - 157850889);
                            v156 = -567090828;
                            break;
                        case 0xDBDA4DCu:
                            v194 = (unsigned int)(-1259945050 * v183 + 550769224);
                            v156 = 947795013;
                            break;
                        case 0x35C39099u:
                            v156 = 1473092505;
                            v183 = __ROR8__(v183, 32) ^ v194;
                            break;
                        case 0x5511A1D1u:
                            v194 = (unsigned int)(9662710 * v194 - 1052055890);
                            v156 = -467555542;
                            break;
                        case 0x620E0B00u:
                            v156 = 153465074;
                            v194 = (unsigned int)v183;
                            break;
                        }
                    }
                    v155 ^= v156;
                } while (v155 != -715179187);
                goto LABEL_1319;
            case 8LL:
                v157 = -1401059616;
               
                v158 = 15852479;
                while (1)
                {
                    if (v157 > 0x8B5FA800)
                    {
                        if (v157 != -1401059616)
                        {
                            if (v157 == -1367522583)
                            {
                                v194 = (unsigned int)(1738929306 * v183 - 1889209659);
                                v183 = __ROL8__(v183, 32);
                                v158 = 142135222;
                            }
                            else if (v157 == -960757920)
                            {
                                v194 = (unsigned int)(-1020796705 * v194 + 2045927347);
                                v183 = __ROL8__(v183, 32);
                                v158 = -1083969707;
                            }
                            goto LABEL_1186;
                        }
                        v158 = 656551648;
                    }
                    else
                    {
                        if (v157 != -1956665344)
                        {
                            switch (v157)
                            {
                            case 0xE90C8DCu:
                                v194 = (unsigned int)(41840847 * v194 + 577215711);
                                v183 = __ROL8__(v183, 32);
                                v158 = 1066419564;
                                break;
                            case 0x79D81035u:
                                v158 = -119622870;
                                v183 ^= v194;
                                break;
                            case 0x8106A31F:
                                v183 = __ROR8__(v183, 32);
                                v158 = 95086830;
                                break;
                            }
                            goto LABEL_1186;
                        }
                        v158 = 1306810208;
                        v183 = __ROL8__(v183, 32) ^ (unsigned int)(-2053775009 * v194 + 288571645);
                    }
                    v194 = (unsigned int)v183;
                LABEL_1186:
                    v157 ^= v158;
                    if (v157 == -2069083151)
                        goto LABEL_1319;
                }
            case 9LL:
                v159 = 1408056962;
                v160 = -849101259;
                do
                {
                    switch (v159)
                    {
                    case 1408056962:
                        v194 = (unsigned int)(-1296148431 * v183 + 1678822514);
                        v160 = -2107510509;
                        v183 = __ROR8__(v183, 32) ^ v194;
                        break;
                    case 1730227930:
                        v183 = __ROL8__(v183 ^ v194, 32);
                        v160 = 1482056554;
                        break;
                    case -1485486187:
                        v194 = (unsigned int)(16464864 * v194 + 1779911046);
                        v160 = 2078473979;
                        break;
                    case -1170041866:
                        v194 = (unsigned int)(-288265349 * v183 + 2089062501);
                        v160 = 80364887;
                        break;
                    case -779300975:
                        v194 = (unsigned int)(-1265239898 * v183 + 1012616060);
                        v183 = __ROL8__(v183, 32);
                        v160 = -1230118581;
                        break;
                    }
                    v159 ^= v160;
                } while (v159 != 1064783280);
                goto LABEL_1319;
            case 10LL:
                v161 = 1190021800;
                
                v162 = 778282410;
                do
                {
                    if (v161 > 0x46EE4AA8)
                    {
                        switch (v161)
                        {
                        case 0x4B4B6D69u:
                            v162 = 1175507701;
                            v194 = (unsigned int)v183;
                            break;
                        case 0x66EB65A0u:
                            v194 = (unsigned int)(-171682270 * v194 + 149894501);
                            v162 = -886195675;
                            break;
                        case 0x92B4798C:
                            v194 = (unsigned int)(1087282763 * v194 - 1367069040);
                            v183 = __ROL8__(v183, 32);
                            v162 = -2031705211;
                            break;
                        }
                    }
                    else
                    {
                        switch (v161)
                        {
                        case 0x46EE4AA8u:
                            v194 = (unsigned int)(64494261 * v183 + 1900749149);
                            v162 = 228927425;
                            v183 = __ROR8__(v183, 32) ^ v194;
                            break;
                        case 0x6A75EE5u:
                            v162 = 1038716998;
                            v183 ^= v194;
                            break;
                        case 0xD5BBF9Cu:
                            v194 = (unsigned int)(-438684520 * v194 - 1238343084);
                            v183 = __ROL8__(v183, 32);
                            v162 = 201122169;
                            break;
                        case 0x3B4ECEA3u:
                            v183 = __ROL8__(v183, 32);
                            v162 = 1180324910;
                            break;
                        }
                    }
                    v161 ^= v162;
                } while (v161 != 2098502285);
                goto LABEL_1319;
            case 11LL:
                v163 = 645655242;
               
                v164 = 140830803;
                do
                {
                    if (v163 > 0x756CE75D)
                    {
                        switch (v163)
                        {
                        case 0x9BD75929:
                            v194 = (unsigned int)(2145370855 * v194 + 776641312);
                            v164 = -2119510370;
                            break;
                        case 0xCD24F2D5:
                            v194 = (unsigned int)(-730236885 * v194 + 169792528);
                            v164 = -1203235448;
                            break;
                        case 0xEC6F9ABE:
                            v194 = (unsigned int)(854374647 * v183 + 1837472016);
                            v183 = __ROL8__(v183, 32);
                            v164 = -973193908;
                            break;
                        }
                    }
                    else
                    {
                        switch (v163)
                        {
                        case 0x756CE75Du:
                            v165 = __ROL8__(v183, 32);
                            v183 = v165 ^ v194;
                            v194 = -1176512972 * ((unsigned int)v165 ^ (unsigned int)v194) - 1765643742;
                            v164 = 91714731;
                            break;
                        case 0x1293744Cu:
                            v164 = 919310305;
                            v183 ^= v194;
                            break;
                        case 0x2458FBADu:
                            v183 = __ROL8__(v183, 32);
                            v164 = 999083583;
                            break;
                        case 0x267BEACAu:
                            v164 = -346089441;
                            v194 = (unsigned int)v183;
                            break;
                        case 0x701B93F6u:
                            v183 = __ROR8__(v183, 32);
                            v164 = 1653139386;
                            break;
                        }
                    }
                    v163 ^= v164;
                } while (v163 != 534001042);
                goto LABEL_1319;
            case 12LL:
                v166 = -658387073;
                
                v167 = -1579206344;
                break;
            case 13LL:
                v169 = -828937925;
               
                v170 = -2109700284;
                do
                {
                    if (v169 > 0xB11856CB)
                    {
                        switch (v169)
                        {
                        case 0xC9CBF67A:
                            v194 = (unsigned int)(-982233137 * v194 - 667608983);
                            v183 = __ROR8__(v183, 32);
                            v170 = -521458978;
                            break;
                        case 0xCE97693B:
                            v170 = 123510593;
                            v194 = (unsigned int)v183;
                            break;
                        case 0xEBCA1A5A:
                            v183 = __ROL8__(v183 ^ v194, 32);
                            v170 = 440978373;
                            break;
                        }
                    }
                    else
                    {
                        switch (v169)
                        {
                        case 0xB11856CB:
                            v194 = (unsigned int)(-1581463050 * v194 + 72247220);
                            v183 = __ROL8__(v183, 32);
                            v170 = 1523731601;
                            break;
                        case 0x2920DCA4u:
                            v170 = -1741125009;
                            v183 ^= v194;
                            v194 = (unsigned int)v183;
                            break;
                        case 0x3D66D6FDu:
                            v194 = (unsigned int)(233088609 * v183 + 1470443078);
                            v183 = __ROR8__(v183, 32);
                            v170 = 1645584240;
                            break;
                        case 0x42CAA043u:
                            v194 = (unsigned int)(-780430287 * v194 + 931128783);
                            v183 = __ROR8__(v183, 32);
                            v170 = 1666197599;
                            break;
                        }
                    }
                    v169 ^= v170;
                } while (v169 != -243084897);
                goto LABEL_1319;
            case 14LL:
                v171 = 92938687;
                v172 = -685223004;
                do
                {
                    if (v171 > 0xC9292B99)
                    {
                        if (v171 == -903843363)
                        {
                            v194 = (unsigned int)(106140909 * v194 + 71579851);
                            v172 = 50944580;
                        }
                        else if (v171 == -507804768)
                        {
                            v194 = (unsigned int)(31181193 * v194 + 768556156);
                            v183 = __ROR8__(v183, 32);
                            v172 = 15724765;
                        }
                    }
                    else
                    {
                        switch (v171)
                        {
                        case 0xC9292B99:
                            v172 = -74571611;
                            v183 = __ROR8__(v183, 32) ^ v194;
                            break;
                        case 0x58A21BFu:
                            v172 = -810921886;
                            v194 = (unsigned int)v183;
                            break;
                        case 0x32A70B3Cu:
                            v194 = (unsigned int)(2065059634 * v183 - 2108097223);
                            v183 = __ROR8__(__ROR8__(v183, 32) ^ v194, 32);
                            v172 = -1843071790;
                            break;
                        case 0x8D479ACA:
                            v194 = (unsigned int)(252673038 * v183 + 465684149);
                            v172 = 212249908;
                            break;
                        }
                    }
                    v171 ^= v172;
                } while (v171 != -1601962002);
                goto LABEL_1319;
            default:
                v173 = -1955903366;
                v174 = 2142671723;
                do
                {
                    if (v173 > 0x6D3C6429)
                    {
                        if (v173 == -1955903366)
                        {
                            v194 = (unsigned int)(27436105 * v183 - 1544613747);
                            v174 = -430494637;
                        }
                        else if (v173 == -193944127)
                        {
                            v183 = __ROR8__(v183, 32);
                            v174 = -1357018544;
                        }
                    }
                    else
                    {
                        switch (v173)
                        {
                        case 0x6D3C6429u:
                            v174 = 1050426691;
                            v183 = __ROR8__(v183, 32) ^ v194;
                            break;
                        case 0x16533C3Fu:
                            v194 = (unsigned int)(-1911345348 * v183 + 702923134);
                            v183 = __ROR8__(v183, 32);
                            v174 = 208837513;
                            break;
                        case 0x1E27C132u:
                            v194 = (unsigned int)(-1574065540 * v194 - 986305121);
                            v174 = -830777003;
                            break;
                        case 0x53A0596Au:
                            v194 = (unsigned int)(-247123085 * v183 + 1509138071);
                            v174 = -1479476053;
                            v183 = __ROL8__(v183, 32) ^ v194;
                            break;
                        }
                    }
                    v173 ^= v174;
                } while (v173 != 1533882257);
                goto LABEL_1319;
            }
            while (2)
            {
                if (v166 > 0x7C360A1C)
                {
                    switch (v166)
                    {
                    case 0x95BCFD2F:
                        v168 = v183 ^ v194;
                        v167 = -890313957;
                    LABEL_1265:
                        v183 = v168;
                        break;
                    case 0x9E48C2F0:
                        v194 = (unsigned int)(43712362 * v194 + 1186415333);
                        v183 = __ROR8__(v183, 32);
                        v167 = 123387859;
                        break;
                    case 0xAFB13B8D:
                        v194 = (unsigned int)(174779216 * v194 + 1962750543);
                        v167 = 266557358;
                        break;
                    case 0xD8C1CF7F:
                        v167 = -445090736;
                        v194 = (unsigned int)v183;
                        break;
                    }
                }
                else
                {
                    switch (v166)
                    {
                    case 0x7C360A1Cu:
                        v183 = __ROR8__(v183, 32);
                        v167 = 184984173;
                        break;
                    case 0x3DB9BB2Fu:
                        v194 = (unsigned int)(24632919 * v194 - 1590474305);
                        v167 = 1099936051;
                        break;
                    case 0x4C0664ADu:
                        v194 = (unsigned int)(1399616130 * v183 + 1890307903);
                        v183 = __ROL8__(v183, 32);
                        v167 = -642082430;
                        break;
                    case 0x5F521E34u:
                        v183 = __ROL8__(v183, 32);
                        v167 = 1680968503;
                        break;
                    case 0x7730A871u:
                        v168 = v183 ^ v194;
                        v167 = 993447132;
                        goto LABEL_1265;
                    }
                }
                v166 ^= v167;
                if (v166 == 996381955)
                    break;
                continue;
            }
        }
    LABEL_1319:
        if (v183 && a1 < maxLocalClients)
            v175 = v183 + 3417888LL * a1;
        else
            v175 = 0LL;
        *(BYTE*)(v175 + 1203754) = a1;
      //  sub_1CF94A0(v175 + 1204152);
      //  sub_85D400((unsigned int)a1, v175 + 1203752);
     //   return sub_85D430(v175 + 1203864);
    


}

  