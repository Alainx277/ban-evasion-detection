#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <winioctl.h>
#endif

#define IOCTL_GET_FINGERPRINT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

#define BIOS_SERIAL_LEN 64

typedef struct _FINGERPRINT_KERNEL {
    // TRUE if any kernel hooks detected
    BOOLEAN kernelHooks;
    // TRUE if test-signed is enabled
    BOOLEAN testSigning;
    CHAR biosSerial[BIOS_SERIAL_LEN];
} FINGERPRINT_KERNEL, *PFINGERPRINT_KERNEL;
