#pragma once
#include <math.h>
#include <iostream>
#include <math.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <cmath>

class Vec2 {
public:
	float x, y;

	// Konstruktoren
	Vec2() : x(0.0f), y(0.0f) {}
	Vec2(float _x, float _y) : x(_x), y(_y) {}

	// Addition
	Vec2 operator+(const Vec2& other) const {
		return Vec2(x + other.x, y + other.y);
	}
	// Subtraktion
	Vec2 operator-(const Vec2& other) const {
		return Vec2(x - other.x, y - other.y);
	}
	// Skalarmultiplikation
	Vec2 operator*(float scalar) const {
		return Vec2(x * scalar, y * scalar);
	}
	// Dot-Product
	float Dot(const Vec2& v) const {
		return x * v.x + y * v.y;
	}
	// Länge
	float Length() const {
		return std::sqrt(x * x + y * y);
	}
	// Distanz zwischen zwei Punkten
	float Distance(const Vec2& v) const {
		float dx = x - v.x;
		float dy = y - v.y;
		return std::sqrt(dx * dx + dy * dy);
	}
};

class Vec3 {
public:
	float x, y, z;

	// Konstruktoren
	Vec3() : x(0.0f), y(0.0f), z(0.0f) {}
	Vec3(float _x, float _y, float _z) : x(_x), y(_y), z(_z) {}

	// Operatoren für +, -
	Vec3 operator+(const Vec3& other) const {
		return Vec3(x + other.x, y + other.y, z + other.z);
	}
	Vec3 operator-(const Vec3& other) const {
		return Vec3(x - other.x, y - other.y, z - other.z);
	}
	// Skalarmultiplikation
	Vec3 operator*(float scalar) const {
		return Vec3(x * scalar, y * scalar, z * scalar);
	}
	friend Vec3 operator*(float scalar, const Vec3& v) {
		return v * scalar;
	}

	// Dot-Product (Skalarprodukt)
	float Dot(const Vec3& v) const {
		return x * v.x + y * v.y + z * v.z;
	}

	// Cross-Product (Vektorprodukt)
	Vec3 Cross(const Vec3& v) const {
		return Vec3(
			y * v.z - z * v.y,
			z * v.x - x * v.z,
			x * v.y - y * v.x
		);
	}

	// Länge und Normalisieren
	float Length() const {
		return std::sqrt(x * x + y * y + z * z);
	}
	void Normalize() {
		float len = Length();
		if (len > 0.0001f) {
			x /= len;
			y /= len;
			z /= len;
		}
	}

	// Distanz
	float Distance(const Vec3& v) const {
		float dx = x - v.x;
		float dy = y - v.y;
		float dz = z - v.z;
		return std::sqrt(dx * dx + dy * dy + dz * dz);
	}
};




typedef LONG(NTAPI* pNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	UINT   ProcessInformationClass,
	PVOID  ProcessInformation,
	ULONG  ProcessInformationLength,
	PULONG ReturnLength
	);

// Für Thread-Information (NtQueryInformationThread)
typedef LONG(NTAPI* pNtQueryInformationThread)(
	HANDLE ThreadHandle,
	UINT   ThreadInformationClass,
	PVOID  ThreadInformation,
	ULONG  ThreadInformationLength,
	PULONG ReturnLength
	);

typedef enum _THREADINFOCLASS_ {
	ThreadBasicInformation = 0
} THREADINFOCLASS_;

typedef struct _THREAD_BASIC_INFORMATION64 {
	NTSTATUS  ExitStatus;
	PVOID     TebBaseAddress;
	CLIENT_ID ClientId;       // struct { HANDLE UniqueProcess; HANDLE UniqueThread; }
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION64, * PTHREAD_BASIC_INFORMATION64;


//Go in CODCaster to search for offsets in the struct
class cg_t
{
public:
	char pad_0x0000[0x1C]; //0x0000
	__int32 renderScreen; //0x001C 
	__int64 serverTime; //0x0020 
	char pad_0x0028[0x28]; //0x0028
	__int32 spectatingID; //0x0050 
	char pad_0x0054[0x2C]; //0x0054
	Vec3 location; //0x0080 
	Vec3 speed_or_sth; //0x008C 
	char pad_0x0098[0x320]; //0x0098
	__int32 health; //0x03B8 
	char pad_0x03BC[0x4]; //0x03BC
	__int32 maxHealth_maybe; //0x03C0 
	char pad_0x03C4[0x2D4]; //0x03C4
	__int32 primaryMagazine; //0x0698 
	__int32 secondaryMagazine; //0x069C 
	char pad_0x06A0[0x34]; //0x06A0
	__int32 primaryAmmo; //0x06D4 
	__int32 seconaryAmmo; //0x06D8 
	char pad_0x06DC[0x964]; //0x06DC

}; //Size=not needed


class cgs_t
{
public:
	char pad_0x0000[0x8]; //0x0000
	__int32 width; //0x0008 
	__int32 height; //0x000C 
	char pad_0x0010[0x18]; //0x0010
	__int32 severTime; //0x0028 
	char pad_0x002C[0x4]; //0x002C
	char gameType[32]; //0x0030 //td, tdm, forntend(lobby) etc.
	char pad_0x0038[0x18]; //0x0038
	char szHostName[256]; //0x0050
	char pad_0x0064[0xEC]; //0x0064
	__int32 maxClients; //0x0150 //depends on the social settings of the player
	char pad_0x0154[0x4]; //0x0154
	char mapFilePath[64]; //0x0158 
	char pad_0x0174[0x24]; //0x0174
	char mapName[32];  //0x0198 
	char pad_0x01A7[0xE99]; //0x01A7

}; //Size=not needed



class refdef_t
{
public:
	char pad_0x0000[0xC]; //0x0000
	__int32 width; //0x000C 
	__int32 height; //0x0010 
	char pad_0x0014[0x64]; //0x0014
	Vec2 tanHalfFov; //0x0078 
	char pad_0x0080[0x8]; //0x0080
	Vec3 viewOrigin; //0x0088 
	char pad_0x0094[0x10]; //0x0094
	Vec3 viewAxis; //0x00A4 
	char pad_0x00B0[0x790]; //0x00B0

}; //Size=not needed


class clientinfo_t
{
public:
	char     pad_0x0000[0xC];   // 0x0000
	char     clientName[32];    // 0x000C (32 chars => 0x20 Bytes)
	__int32  teamID;            // 0x002C
	char     pad_0x0030[0x64];  // 0x0030
	__int32  score;             // 0x0094
	char     pad_0x0098[0x10];  // 0x0098
	__int32  kills;             // 0x00A8
	__int32  deaths;            // 0x00AC
	char     pad_0x00B0[0x44];  // 0x00B0
	__int32  health;            // 0x00F4
	char     pad_0x00F8[0xDD8]; // 0x00F8
}; // Size = 0xED0


class centity_t
{
public:
	char pad_0x0000[0x40]; //0x0000
	Vec3 vOrigin; //0x0040 
	Vec3 vAngles; //0x004C 
	char pad_0x0058[0x308]; //0x0058
	float pitch; //0x0360 
	float yaw; //0x0364 
	char pad_0x0368[0x10]; //0x0368
	__int64 primaryWeaponID; //0x0378 
	__int64 secondaryWeaponID; //0x0380 
	char pad_0x0388[0x70]; //0x0388
	__int32 clientNum; //0x03F8	MAX_PLAYERS: 18
	char pad_0x03FC[0x4]; //0x03FC
	__int32 eFlag; //0x0400		0 or 2: idle, 4 or 6: crouch, 8 or 10: down, 66: shoot, sprint: 131.074U or 0x20002h
	char pad_0x0404[0x4]; //0x0404
	__int32 eType; //0x0408		Player: 0, Bot: 4
	char pad_0x040C[0x8]; //0x040C
	Vec3 Pos; //0x0414 
	char pad_0x0420[0x5E]; //0x0420
	__int8 isAlive; //0x047E	Alive: 3, Dead: 0
	char pad_0x047F[0x481]; // 0x047F

}; //Size=0x900

