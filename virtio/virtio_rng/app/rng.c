/*****************************************************************************
 *
 *   File Name:      rng.c
 *
 *****************************************************************************/
/*****************************************************************************
 * Copyright (C) 2017 Unpublished Work of SUSE. All Rights Reserved.
 *
 * THIS IS AN UNPUBLISHED WORK OF SUES.  IT CONTAINS SUSE'S
 * CONFIDENTIAL, PROPRIETARY, AND TRADE SECRET INFORMATION.  SUSE
 * RESTRICTS THIS WORK TO SUSE EMPLOYEES WHO NEED THE WORK TO PERFORM
 * THEIR ASSIGNMENTS AND TO THIRD PARTIES AUTHORIZED BY SUSE IN WRITING.
 * THIS WORK MAY NOT BE USED, COPIED, DISTRIBUTED, DISCLOSED, ADAPTED,
 * PERFORMED, DISPLAYED, COLLECTED, COMPILED, OR LINKED WITHOUT SUSE'S
 * PRIOR WRITTEN CONSENT.  USE OR EXPLOITATION OF THIS WORK WITHOUT
 * AUTHORIZATION COULD SUBJECT THE PERPETRATOR TO CRIMINAL AND  CIVIL
 * LIABILITY.
 *****************************************************************************/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcrypt.h>
#include <bcrypt_provider.h>


#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_IMPLEMENTED      ((NTSTATUS)0xC0000002L)
#define STATUS_NOT_SUPPORTED        ((NTSTATUS)0xC00000BBL)
#define STATUS_PORT_UNREACHABLE     ((NTSTATUS)0xC000023FL)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER    ((NTSTATUS)0xC000000DL)
#endif

#ifdef USE_IMPORTED_DLL_CODE
DEFINE_GUID(GUID_DEVINTERFACE_VIRT_RNG,
    0x2489fc19, 0xd0fd, 0x4950, 0x83, 0x86, 0xf3, 0xda, 0x3f, 0xa8, 0x5, 0x8);

// CNG RNG Provider Interface.

NTSTATUS WINAPI VirtRngOpenAlgorithmProvider(OUT BCRYPT_ALG_HANDLE *Algorithm,
    IN LPCWSTR AlgId, IN ULONG Flags);

NTSTATUS WINAPI VirtRngGetProperty(IN BCRYPT_HANDLE Object,
    IN LPCWSTR Property, OUT PUCHAR Output, IN ULONG Length,
    OUT ULONG *Result, IN ULONG Flags);

NTSTATUS WINAPI VirtRngSetProperty(IN OUT BCRYPT_HANDLE Object,
    IN LPCWSTR Property, IN PUCHAR Input, IN ULONG Length, IN ULONG Flags);

NTSTATUS WINAPI VirtRngCloseAlgorithmProvider(
    IN OUT BCRYPT_ALG_HANDLE Algorithm, IN ULONG Flags);

NTSTATUS WINAPI VirtRngGenRandom(IN OUT BCRYPT_ALG_HANDLE Algorithm,
    IN OUT PUCHAR Buffer, IN ULONG Length, IN ULONG Flags);

BCRYPT_RNG_FUNCTION_TABLE RngFunctionTable =
{
    // BCRYPT_RNG_INTERFACE_VERSION_1
    1, 0,

    // RNG Interface
    VirtRngOpenAlgorithmProvider,
    VirtRngGetProperty,
    VirtRngSetProperty,
    VirtRngCloseAlgorithmProvider,
    VirtRngGenRandom
};

static NTSTATUS ReadRngFromDevice(IN HANDLE Device,
                                  IN LPOVERLAPPED Overlapped,
                                  IN OUT PUCHAR Buffer,
                                  IN ULONG Length,
                                  OUT LPDWORD BytesRead)
{
    NTSTATUS status;

    if (ReadFile(Device, Buffer, Length, BytesRead, Overlapped) == TRUE)
    {
        status = STATUS_SUCCESS;
    }
    else if (GetLastError() != ERROR_IO_PENDING)
    {
        status = STATUS_UNSUCCESSFUL;
    }
    else if (GetOverlappedResult(Device, Overlapped, BytesRead, TRUE) == TRUE)
    {
        status = STATUS_SUCCESS;
    }
    else
    {
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}

NTSTATUS WINAPI GetRngInterface(IN LPCWSTR pszProviderName,
                                OUT BCRYPT_RNG_FUNCTION_TABLE **ppFunctionTable,
                                IN ULONG dwFlags)
{
    UNREFERENCED_PARAMETER(pszProviderName);
    UNREFERENCED_PARAMETER(dwFlags);

    if (ppFunctionTable == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *ppFunctionTable = &RngFunctionTable;

    return STATUS_SUCCESS;
}

HANDLE OpenVirtRngDeviceInterface()
{
    HDEVINFO devInfo;
    HANDLE devIface = INVALID_HANDLE_VALUE;
    SP_DEVICE_INTERFACE_DATA devIfaceData;
    PSP_DEVICE_INTERFACE_DETAIL_DATA devIfaceDetail = NULL;
    ULONG Length, RequiredLength = 0;
    DWORD Index = 0;
    BOOL bResult;

    devInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_VIRT_RNG, NULL, NULL,
        (DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));

    if (devInfo == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    devIfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    while (SetupDiEnumDeviceInterfaces(devInfo, NULL,
                &GUID_DEVINTERFACE_VIRT_RNG, Index, &devIfaceData) == TRUE)
    {
        SetupDiGetDeviceInterfaceDetail(devInfo, &devIfaceData, NULL, 0,
            &RequiredLength, NULL);

        devIfaceDetail = (PSP_DEVICE_INTERFACE_DETAIL_DATA)
            LocalAlloc(LMEM_FIXED, RequiredLength);

        if (devIfaceDetail == NULL)
        {
            break;
        }

        devIfaceDetail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        Length = RequiredLength;

        bResult = SetupDiGetDeviceInterfaceDetail(devInfo, &devIfaceData,
            devIfaceDetail, Length, &RequiredLength, NULL);

        if (bResult == FALSE)
        {
            LocalFree(devIfaceDetail);
            break;
        }

        devIface = CreateFile(devIfaceDetail->DevicePath, GENERIC_READ,
            FILE_SHARE_READ, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED, NULL);

        LocalFree(devIfaceDetail);

        if (devIface != INVALID_HANDLE_VALUE)
        {
            break;
        }

        Index += 1;
    }

    SetupDiDestroyDeviceInfoList(devInfo);

    return devIface;
}

NTSTATUS WINAPI VirtRngOpenAlgorithmProvider(OUT BCRYPT_ALG_HANDLE *Algorithm,
                                             IN LPCWSTR AlgId,
                                             IN ULONG Flags)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE devIface;

    if (Algorithm == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (lstrcmp(AlgId, BCRYPT_RNG_ALGORITHM) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (Flags != 0L)
    {
        return STATUS_NOT_SUPPORTED;
    }

    devIface = OpenVirtRngDeviceInterface();
    if (devIface == INVALID_HANDLE_VALUE)
    {
        status = STATUS_PORT_UNREACHABLE;
    }

    *Algorithm = (BCRYPT_ALG_HANDLE)devIface;

    return status;
}

NTSTATUS WINAPI VirtRngGetProperty(IN BCRYPT_HANDLE Object,
                                   IN LPCWSTR Property,
                                   OUT PUCHAR Output,
                                   IN ULONG Length,
                                   OUT ULONG *Result,
                                   IN ULONG Flags)
{
    UNREFERENCED_PARAMETER(Object);
    UNREFERENCED_PARAMETER(Output);
    UNREFERENCED_PARAMETER(Property);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Result);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS WINAPI VirtRngSetProperty(IN OUT BCRYPT_HANDLE Object,
                                   IN LPCWSTR Property,
                                   IN PUCHAR Input,
                                   IN ULONG Length,
                                   IN ULONG Flags)
{
    UNREFERENCED_PARAMETER(Object);
    UNREFERENCED_PARAMETER(Property);
    UNREFERENCED_PARAMETER(Input);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS WINAPI VirtRngCloseAlgorithmProvider(IN OUT BCRYPT_ALG_HANDLE Algorithm,
                                              IN ULONG Flags)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE devIface = (HANDLE)Algorithm;
    BOOL bResult;

    UNREFERENCED_PARAMETER(Flags);

    if ((devIface == INVALID_HANDLE_VALUE) || (devIface == NULL))
    {
        return STATUS_INVALID_HANDLE;
    }

    bResult = CloseHandle(devIface);
    if (bResult == FALSE)
    {
        status = STATUS_INVALID_HANDLE;
    }

    return status;
}

NTSTATUS WINAPI VirtRngGenRandom(IN OUT BCRYPT_ALG_HANDLE Algorithm,
                                 IN OUT PUCHAR Buffer,
                                 IN ULONG Length,
                                 IN ULONG Flags)
{
    HANDLE devIface = (HANDLE)Algorithm;
    NTSTATUS status = STATUS_SUCCESS;
    OVERLAPPED ovrlpd;
    DWORD totalBytes;
    DWORD bytesRead;

    if ((devIface == INVALID_HANDLE_VALUE) || (devIface == NULL))
    {
        return STATUS_INVALID_HANDLE;
    }

    if ((Buffer == NULL) || (Length == 0) || (Flags != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }

    ZeroMemory(&ovrlpd, sizeof(ovrlpd));
    totalBytes = 0;

    while (totalBytes < Length)
    {
        status = ReadRngFromDevice(devIface, &ovrlpd, Buffer + totalBytes,
            Length - totalBytes, &bytesRead);

        if (!NT_SUCCESS(status))
        {
            break;
        }

        totalBytes += bytesRead;
    }

    return status;
}
#endif

INT __cdecl
wmain()
{
    HINSTANCE hinst;
    GetRngInterfaceFn pGetRngInterface;
    BCRYPT_RNG_FUNCTION_TABLE *pFunctionTable;
    BCRYPT_ALG_HANDLE Algorithm;
    NTSTATUS ret;
    char buf[8];
    int i;

    hinst = LoadLibrary(TEXT("viorngum.dll"));

    if (!hinst) {
        printf("Couldn't find viorngum.dll\n");
        return 0;
    }

    do {
        pGetRngInterface = (GetRngInterfaceFn)GetProcAddress(
                            hinst,
                            "GetRngInterface");
        if (!pGetRngInterface) {
            printf("Couldn't find GetRngInterface\n");
            break;
        }

#ifdef USE_IMPORTED_DLL_CODE
        ret = GetRngInterface(NULL, &pFunctionTable, 0);
#else
        ret = pGetRngInterface(NULL, &pFunctionTable, 0);
#endif
        if (ret != 0) {
            printf("Failed to get GetRngInterface function table: %x\n", ret);
            break;
        }

        if (ret != 0) {
            printf("Failed to get GetRngInterface function table: %x\n", ret);
            break;
        }
        printf("Major version %d, Minor versin %d\n",
               pFunctionTable->Version.MajorVersion,
               pFunctionTable->Version.MinorVersion);

        ret = pFunctionTable->OpenAlgorithmProvider(
              &Algorithm,
              BCRYPT_RNG_ALGORITHM,
              0);
        if (ret != 0) {
            printf("Failed to open algorithm: %x\n", ret);
            break;
        }

        ret = pFunctionTable->GenRandom(
              Algorithm,
              buf,
              sizeof(buf),
              0);
        if (ret != 0) {
            printf("Failed to read: %x\n", ret);
        } else {
            for (i = 0; i < sizeof(buf); i++) {
                printf("buf[%i] = %x\n", i, buf[i]);
            }
        }

        ret = pFunctionTable->CloseAlgorithmProvider(Algorithm, 0);
        if (ret != 0) {
            printf("Failed to close algorithm: %x\n", ret);
            break;
        }
    } while (0);
    FreeLibrary(hinst);
    return 0;
}
