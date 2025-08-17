#include "stdafx.h"
#include <string>
#include <tracy/Tracy.hpp>
#include "fingerprint.h"
#include "include/sodium/core.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

static void warn(const char* msg)
{
    DWORD err = GetLastError();
    printf("[WARN] %s (Win32 error %lu)\n", msg, (unsigned long)err);
}

extern "C" __declspec (dllexport) bool __stdcall init()
{
	if (sodium_init() == -1) {
        return false;
    }

    const char* appinfo = "anticheat-poc-client";
    TracyAppInfo(appinfo, strlen(appinfo));

	// Create and start anticheat kernel service
	// Currently we treat it as optional
	wchar_t dirBuf[MAX_PATH];
    DWORD len = GetCurrentDirectoryW(MAX_PATH, dirBuf);
    if (len == 0 || len >= MAX_PATH) {
        warn("GetCurrentDirectory failed");
        return true;
    }
    std::wstring driverPath = std::wstring(dirBuf) + L"\\mydriver.sys";

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        warn("OpenSCManager failed (run as Administrator?)");
        return true;
    }

    const wchar_t* svcName = L"anticheat";
    SC_HANDLE svc = OpenServiceW(scm, svcName, SERVICE_ALL_ACCESS);
    if (!svc) {
        svc = CreateServiceW(
            scm,
            svcName,
            svcName,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driverPath.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            warn("CreateService failed");
            CloseServiceHandle(scm);
            return true;
        }
        printf("Created service \"%S\"\n", svcName);
    }

    if (!StartServiceW(svc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("Service \"%S\" already running\n", svcName);
        } else {
            warn("StartService failed");
        }
    } else {
        printf("Service \"%S\" started\n", svcName);
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

	return true;
}

extern "C" __declspec (dllexport) void __stdcall fingerprint(byte** pFingerprint, size_t* pSize)
{
	auto fingerprint = make_fingerprint();

    *pSize = fingerprint.ByteSizeLong();
    *pFingerprint = static_cast<uint8_t*>(CoTaskMemAlloc(*pSize));

    if (*pFingerprint == nullptr)
    {
        *pSize = 0;
        return;
    }

	fingerprint.SerializeToArray(*pFingerprint, *pSize);

	// Assuming the anti cheat component is obfuscated, encrypting and adding a HMAC here
	// would make it harder to spoof on the C# game side

	return;
}

extern "C" __declspec (dllexport) void __stdcall proof(byte* challengeData, size_t challengeSize, byte** pProof, size_t* pSize, uint32_t userId)
{
	FingerprintChallenge challenge{};
	challenge.ParseFromArray(challengeData, challengeSize);

	auto proof = make_proof(challenge, userId);

    *pSize = proof.ByteSizeLong();
    *pProof = static_cast<uint8_t*>(CoTaskMemAlloc(*pSize));

    if (*pProof == nullptr)
    {
        *pSize = 0;
        return;
    }

	proof.SerializeToArray(*pProof, *pSize);

	return;
}
