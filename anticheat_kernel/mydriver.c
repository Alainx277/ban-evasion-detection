#include <ntddk.h>
#include <guiddef.h>
#include <wdm.h>
#include <ntstrsafe.h>

#include "fingerprint_defs.h"

#define FIRMWARE_TABLE_PROVIDER_SMBIOS ((ULONG)'RSMB') // 'RSMB' (Raw SMBIOS)
#define FIRMWARE_TABLE_ACTION_GET_TABLE 1

#pragma pack(push, 1) // Ensure precise packing
typedef struct _SMBIOS_STRUCTURE_HEADER {
    UCHAR   Type;
    UCHAR   Length;
    USHORT  Handle;
} SMBIOS_STRUCTURE_HEADER, *PSMBIOS_STRUCTURE_HEADER;

typedef struct _SMBIOS_TYPE0_INFO {
    SMBIOS_STRUCTURE_HEADER Header;
    UCHAR   Vendor;
    UCHAR   BiosVersion;
    USHORT  BiosStartingAddressSegment;
    UCHAR   BiosReleaseDate;
    UCHAR   BiosRomSize;
    ULONG64 BiosCharacteristics;
} SMBIOS_TYPE0_INFO, *PSMBIOS_TYPE0_INFO;

// System Information
typedef struct _SMBIOS_TYPE1_INFO {
    SMBIOS_STRUCTURE_HEADER Header;
    UCHAR   Manufacturer;
    UCHAR   ProductName;
    UCHAR   Version;
    UCHAR   SerialNumber;
    GUID    UUID;
    UCHAR   WakeUpType;
} SMBIOS_TYPE1_INFO, *PSMBIOS_TYPE1_INFO;

// Baseboard Information
typedef struct _SMBIOS_TYPE2_INFO {
    SMBIOS_STRUCTURE_HEADER Header;
    UCHAR   Manufacturer;
    UCHAR   Product;
    UCHAR   Version;
    UCHAR   SerialNumber;
    UCHAR   AssetTag;
    UCHAR   FeatureFlags;
    UCHAR   LocationInChassis;
    USHORT  ChassisHandle;
    UCHAR   BoardType;
    UCHAR   NumberOfContainedObjectHandles;
    // USHORT  ContainedObjectHandles[]; // Variable length, access based on NumberOfContainedObjectHandles
} SMBIOS_TYPE2_INFO, *PSMBIOS_TYPE2_INFO;

typedef struct RAW_SMBIOS_DATA
{
    UCHAR Used20CallingMethod;
    UCHAR SMBIOSMajorVersion;
    UCHAR SMBIOSMinorVersion;
    UCHAR DmiRevision;
    ULONG Length;
    UCHAR SMBIOSTableData[ANYSIZE_ARRAY];
} RAW_SMBIOS_DATA, *PRAW_SMBIOS_DATA;

#pragma pack(pop)

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
    SystemModuleInformation, // q: RTL_PROCESS_MODULES
    SystemLocksInformation, // q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation, // not implemented
    SystemNonPagedPoolInformation, // not implemented
    SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation, // q: SYSTEM_VDM_INSTEMUL_INFO
    SystemVdmBopInformation, // not implemented // 20
    SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemLoadGdiDriverInformation, // s (kernel-mode only)
    SystemUnloadGdiDriverInformation, // s (kernel-mode only)
    SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
    SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
    SystemObsolete0, // not implemented
    SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
    SystemPrioritySeparation, // s (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation, // s: UNICODE_STRING (requires SeDebugPrivilege) // 40
    SystemVerifierRemoveDriverInformation, // s: UNICODE_STRING (requires SeDebugPrivilege)
    SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
    SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
    SystemSessionCreate, // not implemented
    SystemSessionDetach, // not implemented
    SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
    SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
    SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend, // s (kernel-mode only)
    SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
    SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation, // q: SYSTEM_EXTENDED_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
    SystemComPlusPackage, // q; s: ULONG
    SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
    SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation, // q: ULONG
    SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
    SystemObjectSecurityMode, // q: ULONG // 70
    SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
    SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // NtQuerySystemInformationEx // (kernel-mode only)
    SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemWow64SharedInformationObsolete, // not implemented
    SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
    SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
    SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX // since VISTA
    SystemVerifierTriageInformation, // not implemented
    SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
    SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
    SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege) // NtQuerySystemInformationEx
    SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx, // not implemented
    SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
    SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation, // s (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
    SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
    SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
    SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
    SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
    SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
    SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 100
    SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
    SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
    SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // NtQuerySystemInformationEx // KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
    SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
    SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
    SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
    SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation, // q: BOOT_ENTROPY_NT_RESULT // ExQueryBootEntropyInformation
    SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
    SystemNodeDistanceInformation, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber) // NtQuerySystemInformationEx
    SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
    SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
    SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
    SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
    SystemBadPageInformation, // SYSTEM_BAD_PAGE_INFORMATION
    SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
    SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
    SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemConsoleInformation, // q; s: SYSTEM_CONSOLE_INFORMATION
    SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
    SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
    SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
    SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
    SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
    SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
    SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // since WINBLUE
    SystemCriticalProcessErrorLogInformation, // CRITICAL_PROCESS_EXCEPTION_DATA
    SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
    SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
    SystemEntropyInterruptTimingRawInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
    SystemFullProcessInformation, // q: SYSTEM_EXTENDED_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation, // 150 // (requires SeTcbPrivilege)
    SystemSoftRebootInformation, // q: ULONG
    SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
    SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
    SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
    SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
    SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
    SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 160
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
    SystemCodeIntegrityPolicyInformation, // q; s: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
    SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation, // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
    SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
    SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
    SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation, // q: KAFFINITY_EX // (requires SeIncreaseBasePriorityPrivilege)
    SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
    SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
    SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // NtQuerySystemInformationEx // since REDSTONE
    SystemInterruptSteeringInformation, // q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT // NtQuerySystemInformationEx // 180
    SystemSupportedProcessorArchitectures, // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
    SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
    SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
    SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
    SystemControlFlowTransition, // (Warbird/Encrypt/Decrypt/Execute)
    SystemKernelDebuggingAllowed, // s: ULONG
    SystemActivityModerationExeState, // s: SYSTEM_ACTIVITY_MODERATION_EXE_STATE
    SystemActivityModerationUserSettings, // q: SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
    SystemCodeIntegrityPoliciesFullInformation, // NtQuerySystemInformationEx
    SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
    SystemIntegrityQuotaInformation,
    SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
    SystemProcessorIdleMaskInformation, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
    SystemSecureDumpEncryptionInformation, // NtQuerySystemInformationEx
    SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
    SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
    SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
    SystemFirmwareBootPerformanceInformation,
    SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
    SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
    SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
    SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
    SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
    SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
    SystemCodeIntegrityUnlockModeInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
    SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
    SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
    SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
    SystemCodeIntegritySyntheticCacheInformation, // NtQuerySystemInformationEx
    SystemFeatureConfigurationInformation, // q: in: SYSTEM_FEATURE_CONFIGURATION_QUERY, out: SYSTEM_FEATURE_CONFIGURATION_INFORMATION; s: SYSTEM_FEATURE_CONFIGURATION_UPDATE // NtQuerySystemInformationEx // since 20H1 // 210
    SystemFeatureConfigurationSectionInformation, // q: in: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST, out: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION // NtQuerySystemInformationEx
    SystemFeatureUsageSubscriptionInformation, // q: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS; s: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE
    SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
    SystemSpacesBootInformation, // since 20H2
    SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
    SystemWheaIpmiHardwareInformation,
    SystemDifSetRuleClassInformation, // s: SYSTEM_DIF_VOLATILE_INFORMATION (requires SeDebugPrivilege)
    SystemDifClearRuleClassInformation, // s: NULL (requires SeDebugPrivilege)
    SystemDifApplyPluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION (requires SeDebugPrivilege)
    SystemDifRemovePluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION (requires SeDebugPrivilege) // 220
    SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
    SystemBuildVersionInformation, // q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx // 222
    SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege) // NtQuerySystemInformationEx
    SystemCodeIntegrityAddDynamicStore,
    SystemCodeIntegrityClearDynamicStores,
    SystemDifPoolTrackingInformation,
    SystemPoolZeroingInformation, // q: SYSTEM_POOL_ZEROING_INFORMATION
    SystemDpcWatchdogInformation, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
    SystemDpcWatchdogInformation2, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
    SystemSupportedProcessorArchitectures2, // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 230
    SystemSingleProcessorRelationshipInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor) // NtQuerySystemInformationEx
    SystemXfgCheckFailureInformation, // q: SYSTEM_XFG_FAILURE_INFORMATION
    SystemIommuStateInformation, // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
    SystemHypervisorMinrootInformation, // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
    SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
    SystemPointerAuthInformation, // SYSTEM_POINTER_AUTH_INFORMATION
    SystemSecureKernelDebuggerInformation, // NtQuerySystemInformationEx
    SystemOriginalImageFeatureInformation, // q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemMemoryNumaInformation, // SYSTEM_MEMORY_NUMA_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemMemoryNumaPerformanceInformation, // SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUTSYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT // since 24H2 // 240
    SystemCodeIntegritySignedPoliciesFullInformation,
    SystemSecureCoreInformation, // SystemSecureSecretsInformation
    SystemTrustedAppsRuntimeInformation, // SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION
    SystemBadPageInformationEx, // SYSTEM_BAD_PAGE_INFORMATION
    SystemResourceDeadlockTimeout, // ULONG
    SystemBreakOnContextUnwindFailureInformation, // ULONG (requires SeDebugPrivilege)
    SystemOslRamdiskInformation, // SYSTEM_OSL_RAMDISK_INFORMATION
    SystemCodeIntegrityPolicyManagementInformation, // since 25H2
    SystemMemoryNumaCacheInformation,
    SystemProcessorFeaturesBitMapInformation,
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

// Forward declarations
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DispatchDefault(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
VOID SmbiosIdentifiers(VOID);
PCHAR GetSmbiosStringInternal(PSMBIOS_STRUCTURE_HEADER pStructure, UCHAR stringNum, PCHAR smbiosDataEnd);

// Globals

static CHAR g_BiosSerial[BIOS_SERIAL_LEN] = {0};
static BOOLEAN g_DriverHook = FALSE;
static BOOLEAN g_TestSign = FALSE;

// Helper function to retrieve a specific string from an SMBIOS structure's string section.
PCHAR GetSmbiosStringInternal(PSMBIOS_STRUCTURE_HEADER pStructure, UCHAR stringNum, PCHAR smbiosDataEnd) {
    PCHAR stringTableStart;
    PCHAR currentString;
    UCHAR i;

    PAGED_CODE();

    if (stringNum == 0) {
        return "N/A";
    }

    // Strings start immediately after the formatted part of the structure.
    stringTableStart = (PCHAR)pStructure + pStructure->Length;

    if (stringTableStart + 1 >= smbiosDataEnd) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "AnticheatPoc: String table for type %d (len %d) is too short or out of bounds. StringTableStart: %p, smbiosDataEnd: %p\n",
                   pStructure->Type, pStructure->Length, stringTableStart, smbiosDataEnd);
        return "[Error: StringTable OOB/short]";
    }

    currentString = stringTableStart;
    for (i = 1; i < stringNum; i++) {
        // Move to the end of the current string.
        while (currentString < smbiosDataEnd && *currentString != '\0') {
            currentString++;
        }
        if (currentString >= smbiosDataEnd) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "AnticheatPoc: Malformed string table (no null term) for type %d, seeking string index %d (found %d).\n", pStructure->Type, stringNum, i);
            return "[Error: Malformed string (no null)]";
        }
        currentString++;

        if (currentString >= smbiosDataEnd || *currentString == '\0') {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "AnticheatPoc: String index %d not found for type %d (EOS or OOB after skipping %d strings).\n", stringNum, pStructure->Type, i);
            return "[Error: String index not found]";
        }
    }

    // currentString now points to the beginning of the desired string.
    // Final check: ensure this pointer is valid.
    if (currentString >= smbiosDataEnd) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "AnticheatPoc: Target string %d for type %d is out of bounds.\n", stringNum, pStructure->Type);
        return "[Error: Target String OOB]";
    }

    // Ensure the target string itself is null-terminated within the buffer to prevent DbgPrintEx from reading OOB.
    PCHAR tempEnd = currentString;
    while (tempEnd < smbiosDataEnd && *tempEnd != '\0') {
        tempEnd++;
    }
    if (tempEnd >= smbiosDataEnd) { // Reached end of buffer without finding null for this string.
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "AnticheatPoc: Target string %d for type %d is not null-terminated within bounds.\n", stringNum, pStructure->Type);
        return "[Error: Unterminated target string]";
    }
    
    // Handle valid empty strings (e.g., string index points to a '\0' immediately).
    if (*currentString == '\0' && currentString < smbiosDataEnd) {
        return ""; // Return an empty C-string literal.
    }

    return currentString;
}

VOID SmbiosIdentifiers(VOID) {
    NTSTATUS status;
    PSYSTEM_FIRMWARE_TABLE_INFORMATION pFirmwareTableInfoAlloc = NULL;
    PVOID pSmbiosData = NULL;
    ULONG smbiosDataLengthActual = 0;
    ULONG requiredTotalBufferSize;

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: Attempting to read SMBIOS table...\n");

    //  Determine the size of the SMBIOS data buffer required.
    ULONG initialInfoStructHeaderSize = FIELD_OFFSET(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer);
    PSYSTEM_FIRMWARE_TABLE_INFORMATION pTempInfo = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)ExAllocatePoolWithTag(
        PagedPool, initialInfoStructHeaderSize, '0SMI'); // Tag: SMBIOS query 0

    if (!pTempInfo) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AnticheatPoc: Failed to allocate temp buffer for SMBIOS size query.\n");
        return;
    }

    pTempInfo->ProviderSignature = FIRMWARE_TABLE_PROVIDER_SMBIOS;
    pTempInfo->Action = FIRMWARE_TABLE_ACTION_GET_TABLE;
    pTempInfo->TableID = 0;
    pTempInfo->TableBufferLength = 0;

    status = ZwQuerySystemInformation(
        SystemFirmwareTableInformation,
        pTempInfo,
        initialInfoStructHeaderSize,
        &requiredTotalBufferSize
    );

    ULONG smbiosDataSizeNeeded = 0;
    if (status == STATUS_BUFFER_TOO_SMALL) {
        // This is expected. pTempInfo->TableBufferLength now contains the size of the SMBIOS data.
        smbiosDataSizeNeeded = pTempInfo->TableBufferLength;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: SMBIOS data size required: %lu bytes.\n", smbiosDataSizeNeeded);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "AnticheatPoc: ZwQuerySystemInformation (get size) failed or returned unexpected status 0x%X. Required total size: %lu\n",
                   status, requiredTotalBufferSize);
        ExFreePoolWithTag(pTempInfo, '0SMI');
        return;
    }
    ExFreePoolWithTag(pTempInfo, '0SMI');
    pTempInfo = NULL;

    if (smbiosDataSizeNeeded == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AnticheatPoc: SMBIOS data length from query is zero.\n");
        return;
    }

    // Allocate the full buffer for SYSTEM_FIRMWARE_TABLE_INFORMATION + SMBIOS data.
    ULONG fullAllocSize = FIELD_OFFSET(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer) + smbiosDataSizeNeeded;
    pFirmwareTableInfoAlloc = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)ExAllocatePoolWithTag(
        PagedPool, fullAllocSize, '1SMI'); // Tag: SMBIOS query 1

    if (!pFirmwareTableInfoAlloc) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AnticheatPoc: Failed to allocate full buffer for SMBIOS data (size %lu).\n", fullAllocSize);
        return;
    }

    pFirmwareTableInfoAlloc->ProviderSignature = FIRMWARE_TABLE_PROVIDER_SMBIOS;
    pFirmwareTableInfoAlloc->Action = FIRMWARE_TABLE_ACTION_GET_TABLE;
    pFirmwareTableInfoAlloc->TableID = 0;
    pFirmwareTableInfoAlloc->TableBufferLength = smbiosDataSizeNeeded;

    ULONG bytesWritten = 0;
    status = ZwQuerySystemInformation(
        SystemFirmwareTableInformation,
        pFirmwareTableInfoAlloc,
        fullAllocSize,
        &bytesWritten
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AnticheatPoc: ZwQuerySystemInformation (get data) failed with status 0x%X.\n", status);
        ExFreePoolWithTag(pFirmwareTableInfoAlloc, '1SMI');
        return;
    }

    pSmbiosData = pFirmwareTableInfoAlloc->TableBuffer;
    smbiosDataLengthActual = pFirmwareTableInfoAlloc->TableBufferLength;

    PRAW_SMBIOS_DATA raw = (PRAW_SMBIOS_DATA)pSmbiosData;
    pSmbiosData       = raw->SMBIOSTableData;
    smbiosDataLengthActual = raw->Length;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: SMBIOS data retrieved. Actual data length in TableBuffer: %lu bytes. BytesWritten by API: %lu\n",
               smbiosDataLengthActual, bytesWritten);

    if (smbiosDataLengthActual == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "AnticheatPoc: SMBIOS data length in buffer is zero after successful query.\n");
        ExFreePoolWithTag(pFirmwareTableInfoAlloc, '1SMI');
        return;
    }

    PCHAR smbiosDataEnd = (PCHAR)pSmbiosData + smbiosDataLengthActual;

    // Parse the SMBIOS data.
    PUCHAR currentPtr = (PUCHAR)pSmbiosData;
    while (currentPtr < (PUCHAR)smbiosDataEnd) {
        PSMBIOS_STRUCTURE_HEADER pHeader = (PSMBIOS_STRUCTURE_HEADER)currentPtr;

        if (currentPtr + sizeof(SMBIOS_STRUCTURE_HEADER) > (PUCHAR)smbiosDataEnd) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "AnticheatPoc: Not enough data for SMBIOS_STRUCTURE_HEADER at offset %td.\n", currentPtr - (PUCHAR)pSmbiosData);
            break;
        }

        if (currentPtr + pHeader->Length > (PUCHAR)smbiosDataEnd) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "AnticheatPoc: Structure (type %d, handle 0x%X) formatted length %d exceeds buffer end. Offset %td.\n",
                       pHeader->Type, pHeader->Handle, pHeader->Length, currentPtr - (PUCHAR)pSmbiosData);
            break;
        }

        // Check for invalid structure length. Smallest valid SMBIOS structure (Type 127) has Length 4.
        if (pHeader->Length < sizeof(SMBIOS_STRUCTURE_HEADER)) {
             DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "AnticheatPoc: Structure (type %d, handle 0x%X) has invalid length %d. Min expected %Iu. Offset %td. Terminating parse.\n",
                       pHeader->Type, pHeader->Handle, pHeader->Length, sizeof(SMBIOS_STRUCTURE_HEADER), currentPtr - (PUCHAR)pSmbiosData);
            break;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: SMBIOS Type: %d, Length: %d, Handle: 0x%X\n",
                   pHeader->Type, pHeader->Length, pHeader->Handle);

        // Process specific SMBIOS structure types
        if (pHeader->Type == 0) { // BIOS Information
            PSMBIOS_TYPE0_INFO pType0 = (PSMBIOS_TYPE0_INFO)pHeader;
            if (pHeader->Length >= FIELD_OFFSET(SMBIOS_TYPE0_INFO, BiosCharacteristics)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  BIOS Vendor: %s\n", GetSmbiosStringInternal(pHeader, pType0->Vendor, smbiosDataEnd));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  BIOS Version: %s\n", GetSmbiosStringInternal(pHeader, pType0->BiosVersion, smbiosDataEnd));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  BIOS Release Date: %s\n", GetSmbiosStringInternal(pHeader, pType0->BiosReleaseDate, smbiosDataEnd));
            }
        } else if (pHeader->Type == 1) { // System Information
            PSMBIOS_TYPE1_INFO pType1 = (PSMBIOS_TYPE1_INFO)pHeader;
            if (pHeader->Length >= FIELD_OFFSET(SMBIOS_TYPE1_INFO, WakeUpType)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  System Manufacturer: %s\n", GetSmbiosStringInternal(pHeader, pType1->Manufacturer, smbiosDataEnd));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  System Product Name: %s\n", GetSmbiosStringInternal(pHeader, pType1->ProductName, smbiosDataEnd));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  System Version: %s\n", GetSmbiosStringInternal(pHeader, pType1->Version, smbiosDataEnd));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  System Serial Number: %s\n", GetSmbiosStringInternal(pHeader, pType1->SerialNumber, smbiosDataEnd));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  System UUID: %08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
                           pType1->UUID.Data1, pType1->UUID.Data2, pType1->UUID.Data3,
                           pType1->UUID.Data4[0], pType1->UUID.Data4[1], pType1->UUID.Data4[2], pType1->UUID.Data4[3],
                           pType1->UUID.Data4[4], pType1->UUID.Data4[5], pType1->UUID.Data4[6], pType1->UUID.Data4[7]);
            }
        } else if (pHeader->Type == 2) { // Baseboard Information
            PSMBIOS_TYPE2_INFO pType2 = (PSMBIOS_TYPE2_INFO)pHeader;
            if (pHeader->Length >= FIELD_OFFSET(SMBIOS_TYPE2_INFO, BoardType)) { // Ensure fields up to BoardType exist
                PCHAR serial = GetSmbiosStringInternal(pHeader, pType2->SerialNumber, smbiosDataEnd);
                // Store the BIOS serial to later return in the device control
                RtlStringCchCopyA(g_BiosSerial, ARRAYSIZE(g_BiosSerial), serial);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  Baseboard Manufacturer: %s\n", GetSmbiosStringInternal(pHeader, pType2->Manufacturer, smbiosDataEnd));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  Baseboard Product: %s\n", GetSmbiosStringInternal(pHeader, pType2->Product, smbiosDataEnd));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  Baseboard Version: %s\n", GetSmbiosStringInternal(pHeader, pType2->Version, smbiosDataEnd));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  Baseboard Serial Number: %s\n", serial);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "  Baseboard Asset Tag: %s\n", GetSmbiosStringInternal(pHeader, pType2->AssetTag, smbiosDataEnd));
            }
        }

        // Move to the next structure.
        // First, skip the formatted part of the current structure.
        PUCHAR pEndOfFormattedPart = currentPtr + pHeader->Length;
        PUCHAR pNextStructureStart = pEndOfFormattedPart;

        // Check if the end of the formatted part is already out of bounds.
        if (pNextStructureStart >= (PUCHAR)smbiosDataEnd) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: End of formatted part for Type %d is at/beyond SMBIOS data end. Offset %td.\n",
                       pHeader->Type, pNextStructureStart - (PUCHAR)pSmbiosData);
            currentPtr = (PUCHAR)smbiosDataEnd;
            continue;
        }

        // Then, skip the string section that follows. The string section ends with two null bytes (\0\0).
        // Scan for this double null.
        while(pNextStructureStart + 1 < (PUCHAR)smbiosDataEnd) {
            if (*pNextStructureStart == 0 && *(pNextStructureStart + 1) == 0) {
                break;
            }
            pNextStructureStart++;
        }

        // After the loop, pNextStructureStart points to the first of the two nulls, or near smbiosDataEnd.
        if (pNextStructureStart + 1 < (PUCHAR)smbiosDataEnd && *pNextStructureStart == 0 && *(pNextStructureStart + 1) == 0) {
            currentPtr = pNextStructureStart + 2;
        } else {
            // Did not find a clear double null before the end of the buffer.
            // This could mean the table is malformed or this is the last structure and its string section ends precisely at the buffer end.
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "AnticheatPoc: No double null found for string section of Type %d, or end of table reached. Current offset %td. Terminating parse.\n",
                       pHeader->Type, pNextStructureStart-(PUCHAR)pSmbiosData);
            currentPtr = (PUCHAR)smbiosDataEnd; // Force loop termination.
        }

        // SMBIOS Type 127 is the end-of-table marker.
        if (pHeader->Type == 127) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: Found SMBIOS End-of-Table marker (Type 127). Offset %td.\n", (PUCHAR)pHeader - (PUCHAR)pSmbiosData);
            break; // Stop parsing.
        }
    }

    ExFreePoolWithTag(pFirmwareTableInfoAlloc, '1SMI');
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: Finished SMBIOS parsing.\n");
}

typedef struct _OBJECT_DIRECTORY_INFORMATION
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

__declspec(dllimport) POBJECT_TYPE *IoDriverObjectType;
__declspec(dllimport) ERESOURCE *PsLoadedModuleResource;

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenDirectoryObject(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryDirectoryObject(
    _In_ HANDLE DirectoryHandle,
    _Out_writes_bytes_opt_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext OPTIONAL,
    PVOID* Object
    );

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID      DllBase;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

extern PLIST_ENTRY PsLoadedModuleList;

typedef struct _MODULE_RANGE {
    ULONG_PTR Base;
    ULONG_PTR Limit;
} MODULE_RANGE, *PMODULE_RANGE;

static const UNICODE_STRING g_DriverType =
    RTL_CONSTANT_STRING(L"Driver");

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

PRTL_PROCESS_MODULES g_ModuleInformation = NULL;
ULONG g_ModuleInformationSize = 0;

BOOLEAN IsAddressInValidKernelModule(PVOID Address) {
    if (!g_ModuleInformation) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[IRPScan] Module information not loaded.\n");
        return FALSE; // Cannot validate
    }

    for (ULONG i = 0; i < g_ModuleInformation->NumberOfModules; ++i) {
        PRTL_PROCESS_MODULE_INFORMATION module = &g_ModuleInformation->Modules[i];
        if (Address >= module->ImageBase &&
            Address < (PVOID)((PUCHAR)module->ImageBase + module->ImageSize)) {
            return TRUE;
        }
    }
    return FALSE;
}

VOID ScanDriverIrpHandlers(PDRIVER_OBJECT DriverObject) {
    if (!DriverObject) {
        return;
    }

    // DriverName might not always be available or could be spoofed, but useful for reporting
    UNICODE_STRING driverName = DriverObject->DriverName;
    if (driverName.Buffer == NULL || driverName.Length == 0) {
        RtlInitUnicodeString(&driverName, L"<Unknown Driver>");
    }


    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[IRPScan] Scanning Driver: %wZ (Object @ %p)\n",
               &driverName, DriverObject);

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) {
        PDRIVER_DISPATCH irpHandler = DriverObject->MajorFunction[i];

        if (irpHandler != NULL) {
            if (!IsAddressInValidKernelModule(irpHandler)) {
                g_DriverHook = TRUE;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[IRPScan] SUSPICIOUS IRP Handler for Driver %wZ:\n"
                           "           IRP_MJ Code: 0x%X\n"
                           "           Handler Address: %p (NOT in a valid module!)\n",
                           &driverName, i, irpHandler);
            } else {
                 // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "[IRPScan] Driver %wZ, IRP_MJ[0x%X] -> %p (OK)\n", &driverName, i, irpHandler);
            }
        }
    }
}

NTSTATUS RefreshSystemModuleInformation() {
    NTSTATUS status;
    ULONG requiredSize = 0;

    if (g_ModuleInformation) {
        ExFreePoolWithTag(g_ModuleInformation, 'lMdS');
        g_ModuleInformation = NULL;
        g_ModuleInformationSize = 0;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &requiredSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[IRPScan] ZwQuerySystemInformation (1st call) failed: 0x%X\n", status);
        return status;
    }

    g_ModuleInformationSize = requiredSize;
    g_ModuleInformation = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, g_ModuleInformationSize, 'lMdS');

    if (!g_ModuleInformation) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[IRPScan] Failed to allocate memory for module list.\n");
        g_ModuleInformationSize = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, g_ModuleInformation, g_ModuleInformationSize, &requiredSize);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[IRPScan] ZwQuerySystemInformation (2nd call) failed: 0x%X\n", status);
        ExFreePoolWithTag(g_ModuleInformation, 'lMdS');
        g_ModuleInformation = NULL;
        g_ModuleInformationSize = 0;
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[IRPScan] Successfully retrieved %d modules.\n", g_ModuleInformation->NumberOfModules);
    return STATUS_SUCCESS;
}

NTSTATUS ScanIrpHandlers() {
    NTSTATUS status;
    ULONG requiredSize = 0;
    HANDLE dirHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING dirName;

    PAGED_CODE();

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[IRPScan] Must be called at PASSIVE_LEVEL.\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = RefreshSystemModuleInformation();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[IRPScan] Failed to refresh system module information: 0x%X\n", status);
        return status;
    }

    // Enumerate Driver Objects from \Driver directory
    RtlInitUnicodeString(&dirName, L"\\Driver");
    InitializeObjectAttributes(&objAttr, &dirName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenDirectoryObject(&dirHandle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &objAttr);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[IRPScan] Failed to open \\Driver directory: 0x%X\n", status);
        ExFreePoolWithTag(g_ModuleInformation, 'lMdS');
        g_ModuleInformation = NULL;
        g_ModuleInformationSize = 0;
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[IRPScan] Opened \\Driver directory.\n");

    ULONG context = 0;
    BOOLEAN firstQuery = TRUE;
    UCHAR buffer[1024];
    POBJECT_DIRECTORY_INFORMATION dirInfo = (POBJECT_DIRECTORY_INFORMATION)buffer;

    while (TRUE) {
        status = ZwQueryDirectoryObject(dirHandle, dirInfo, sizeof(buffer), TRUE, firstQuery, &context, &requiredSize);
        firstQuery = FALSE;

        if (!NT_SUCCESS(status)) {
            if (status == STATUS_NO_MORE_ENTRIES) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[IRPScan] No more entries in \\Driver.\n");
                status = STATUS_SUCCESS;
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[IRPScan] ZwQueryDirectoryObject failed: 0x%X\n", status);
            }
            break;
        }

        // Check if Name and TypeName are valid before using
        if (dirInfo->Name.Buffer && dirInfo->Name.Length > 0 &&
            dirInfo->TypeName.Buffer && dirInfo->TypeName.Length > 0) {

            // We are interested in objects of type "Driver"
            if (RtlCompareUnicodeString(&dirInfo->TypeName, &g_DriverType, TRUE) == 0) {
                UNICODE_STRING objectName;
                WCHAR objectNameBuffer[256]; // Buffer for "\Driver\" + dirInfo->Name

                // Construct full path: \Driver\<name>
                RtlInitEmptyUnicodeString(&objectName, objectNameBuffer, sizeof(objectNameBuffer));
                RtlAppendUnicodeToString(&objectName, L"\\Driver\\");
                RtlAppendUnicodeStringToString(&objectName, &dirInfo->Name);

                PDRIVER_OBJECT pDriverObject = NULL;
                NTSTATUS refStatus = ObReferenceObjectByName(
                    &objectName,
                    OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                    NULL,
                    0,
                    *IoDriverObjectType,
                    KernelMode,
                    NULL,
                    (PVOID*)&pDriverObject
                );

                if (NT_SUCCESS(refStatus) && pDriverObject) {
                    ScanDriverIrpHandlers(pDriverObject);
                    ObDereferenceObject(pDriverObject);
                } else {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[IRPScan] Failed to reference driver %wZ: 0x%X\n", &objectName, refStatus);
                }
            }
        } else {
             DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "[IRPScan] ZwQueryDirectoryObject returned entry with NULL Name/TypeName.\n");
        }
    }

    if (dirHandle) {
        ZwClose(dirHandle);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[IRPScan] Scan completed.\n");
    return status;
}

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION;

BOOLEAN
IsTestSignModeEnabled()
{
    UNICODE_STRING dllName;
    PVOID hNtdll;
    SYSTEM_CODEINTEGRITY_INFORMATION sci;
    NTSTATUS status;

    sci.Length = sizeof(sci);
    status = ZwQuerySystemInformation(
        SystemCodeIntegrityInformation,
        &sci,
        sizeof(sci),
        NULL);

    // Check if integrity checks are disabled or test signing is on
    if (NT_SUCCESS(status) && (
        (sci.CodeIntegrityOptions & 0x2) ||
        !(sci.CodeIntegrityOptions & 0x1)))
    {
        return TRUE;
    }
    return FALSE;
}

// DriverEntry: Initializes the driver.
NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLinkName;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "AnticheatPoc: DriverEntry\n");

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&deviceName, L"\\Device\\AnticheatPoc");
    RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\AnticheatPoc");

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &DeviceObject);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AnticheatPoc: IoCreateDevice failed with status 0x%X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AnticheatPoc: IoCreateSymbolicLink failed with status 0x%X\n", status);
        IoDeleteDevice(DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    // Initialize other major functions to a default handler
    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
        if (DriverObject->MajorFunction[i] == NULL) {
            DriverObject->MajorFunction[i] = DispatchDefault;
        }
    }
    DriverObject->DriverUnload = DriverUnload;

    SmbiosIdentifiers();
    ScanIrpHandlers();
    g_TestSign = IsTestSignModeEnabled();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "AnticheatPoc: End DriverEntry\n");

    return STATUS_SUCCESS;
}

// DriverUnload: Cleans up resources when the driver is unloaded.
VOID
DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLinkName;

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: DriverUnload\n");

    RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\AnticheatPoc");
    IoDeleteSymbolicLink(&symLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: End DriverUnload\n");
}

// DispatchCreate: Handles IRP_MJ_CREATE requests.
NTSTATUS
DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: DispatchCreate\n");
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// DispatchClose: Handles IRP_MJ_CLOSE requests.
NTSTATUS
DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: DispatchClose\n");
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// DispatchDefault: Handles any IRP major functions not explicitly handled.
NTSTATUS
DispatchDefault(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: DispatchDefault for Major Function 0x%X\n", irpSp->MajorFunction);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG bytes = 0;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: Processing IOCTL\n");
    if (code == IOCTL_GET_FINGERPRINT) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: Processing IOCTL fingerprint\n");
        ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
        if (outLen < sizeof(FINGERPRINT_KERNEL)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: Buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            bytes  = sizeof(FINGERPRINT_KERNEL);
        } else {
            PFINGERPRINT_KERNEL out = (PFINGERPRINT_KERNEL)Irp->AssociatedIrp.SystemBuffer;
            RtlZeroMemory(out, sizeof(*out));

            out->kernelHooks = g_DriverHook;
            out->testSigning = g_TestSign;

            // Copy the cached BIOS serial
            RtlStringCchCopyA(out->biosSerial, BIOS_SERIAL_LEN, g_BiosSerial);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AnticheatPoc: IOCTL fingerprint success\n");
            status = STATUS_SUCCESS;
            bytes  = sizeof(*out);
        }
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = bytes;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
