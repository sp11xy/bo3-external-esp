#pragma once
#include "structs.h"

uint64_t __ROR8__(uint64_t value, int count);
uint64_t __ROL8__(uint64_t x, int count);

uintptr_t GetEncryptedPointer(HANDLE hProcess, uintptr_t baseAddress, uintptr_t offset);
uint64_t GetSwitchCaseValue(HANDLE hProcess);
uintptr_t GetDword53A2720(HANDLE hProcess, uintptr_t baseAddress);
uint64_t pCG_t_Decryption(uint64_t encrypted_value, bool retaddrIsBig, HANDLE hProcess);
uint64_t pCGs_Array_Decryption(uint64_t encrypted_value, int clientNum, bool retaddrIsBig, HANDLE hProcess);
uint64_t pCEntity(uint64_t enrypted_pointer_CG, HANDLE hProcess, uintptr_t base, int localClientNum);