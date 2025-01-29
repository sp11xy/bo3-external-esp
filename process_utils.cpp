#include "process_utils.h"
#include "structs.h"

//uintptr_t cus we wanna return a "raw" adress and it can hold 32bit and also 64bit addys
//DWORD cus WindowsAPI is using DWORD for the the procID
//std::wstring cus WinAPI is using Unicode/wideString (2 or 4 bytes per char)
//const means that the function itself will not modify the strings and makes it safer
//& passes as reference so we dont have to copy whole thing
uintptr_t GetModuleBaseAddy(DWORD procID, const std::wstring& moduleName)
{
    uintptr_t baseAddy = 0;

    //takes a snapshot of the Process, Thread or module informations of the windows struct
    //TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32: we wanna have a snapshot of all modules in a process
    //snapShot now helds a token/key/id which is important for the winAPI to get more infos
    HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procID);


    if (snapShot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W moduleEntry; //windows struct which yields infos about baseAddys and modulenames etc.
        moduleEntry.dwSize = sizeof(MODULEENTRY32W); //we set the size in bytes, its just a safety measure from windows

        //&moduleEntry is the adress of our struct of the the first module 
        //return true when we sucessfully read and moduleEntry the first module is
        //false when no entry can be found or error occured
        if (Module32FirstW(snapShot, &moduleEntry)) //reads the first module from the snapshot
        {
            do
            {
                //"Cast" szModule to a std::wstring so we can compare it 
                if (std::wstring(moduleEntry.szModule) == moduleName)
                {
                    baseAddy = reinterpret_cast<uintptr_t>(moduleEntry.modBaseAddr);
                    break;
                }
            } while (Module32NextW(snapShot, &moduleEntry)); //gets the next module until it reaches the end and return 0

        }
        CloseHandle(snapShot); //Windows-Handles need to be closed everytime you finished using it!!
    }
    return baseAddy;
}


DWORD GetProcessIdByName(const std::wstring& processName) {
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (processName.compare(pe32.szExeFile) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}


uintptr_t GetPebAddress(HANDLE hProcess)
{
    std::cout << "[DEBUG] Lade ntdll.dll...\n";
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
    {
        std::cerr << "[!] ntdll.dll nicht gefunden.\n";
        return 0;
    }
    std::cout << "[DEBUG] ntdll.dll gefunden bei: 0x" << std::hex << (uintptr_t)hNtdll << "\n";

    // Funktionszeiger auf NtQueryInformationProcess holen
    auto NtQueryInformationProcess_ =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess_)
    {
        std::cerr << "[!] NtQueryInformationProcess nicht gefunden.\n";
        return 0;
    }
    std::cout << "[DEBUG] NtQueryInformationProcess bei: 0x" << std::hex
        << (uintptr_t)NtQueryInformationProcess_ << "\n";

    PROCESS_BASIC_INFORMATION pbi{};
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryInformationProcess_(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status < 0)
    {
        std::cerr << "[!] NtQueryInformationProcess schlug fehl. NTSTATUS = 0x"
            << std::hex << status << "\n";
        return 0;
    }

    std::cout << "[DEBUG] NtQueryInformationProcess erfolgreich.\n";
    std::cout << "[DEBUG] PEB-Adresse im Zielprozess: 0x"
        << std::hex << (uintptr_t)pbi.PebBaseAddress << "\n";

    // Hier steht die PEB-Adresse (im Target-Prozess)
    return reinterpret_cast<uintptr_t>(pbi.PebBaseAddress);
}


DWORD GetMainThreadId(DWORD dwProcessId)
{
    DWORD mainThreadId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te32{};
        te32.dwSize = sizeof(te32);
        if (Thread32First(hSnap, &te32))
        {
            do {
                if (te32.th32OwnerProcessID == dwProcessId)
                {
                    mainThreadId = te32.th32ThreadID;
                    break;  // wir nehmen den ersten passenden
                }
            } while (Thread32Next(hSnap, &te32));
        }
        CloseHandle(hSnap);
    }
    return mainThreadId;
}


PVOID GetTebBaseAddressOfThread(HANDLE hThread)
{
    // Laden der ntdll.dll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cerr << "[!] Konnte ntdll.dll nicht laden\n";
        return nullptr;
    }

    // Funktionszeiger auf NtQueryInformationThread erstellen
    auto NtQueryInformationThread_ =
        (pNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
    if (!NtQueryInformationThread_) {
        std::cerr << "[!] Konnte NtQueryInformationThread nicht finden\n";
        return nullptr;
    }

    THREAD_BASIC_INFORMATION64 tbi64{};
    ULONG retLen = 0;

    NTSTATUS status = NtQueryInformationThread_(
        hThread,
        ThreadBasicInformation,
        &tbi64,
        sizeof(tbi64),   // = 48
        &retLen
    );

    if (status < 0) {
        std::cerr << "[!] NtQueryInformationThread fehlgeschlagen. NTSTATUS="
            << std::hex << status << "\n";
        return nullptr;
    }

    return tbi64.TebBaseAddress;
}

HWND FindMainWindow(DWORD pid) {
    struct data {
        DWORD pid;
        HWND hwnd;
    };

    data d = { pid, nullptr };
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        data& d = *reinterpret_cast<data*>(lParam);
        DWORD currentPid;
        GetWindowThreadProcessId(hwnd, &currentPid);

        if (currentPid == d.pid && GetWindow(hwnd, GW_OWNER) == 0 && IsWindowVisible(hwnd)) {
            d.hwnd = hwnd;
            return FALSE;
        }
        return TRUE;
        }, reinterpret_cast<LPARAM>(&d));

    return d.hwnd;
}