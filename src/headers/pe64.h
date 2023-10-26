#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifndef PE64_H
#define PE64_H

//List of structs

struct IMAGE_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
};

//Subsystem
#define IMAGE_SUBSYSTEM_UNKNOWN 0
#define IMAGE_SUBSYSTEM_NATIVE 1
#define IMAGE_SUBSYSTEM_WINDOWS_GUI 2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI 3
#define IMAGE_SUBSYSTEM_OS2_CUI 5
#define IMAGE_SUBSYSTEM_POSIX_CUI 7
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS 8
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI 9
#define IMAGE_SUBSYSTEM_EFI_APPLICATION 10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER 12
#define IMAGE_SUBSYSTEM_EFI_ROM 13
#define IMAGE_SUBSYSTEM_XBOX 14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

//DLL Characteristics
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA 0x0020
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY 0x0080
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200
#define IMAGE_DLLCHARACTERISTICS_NO_SEH 0x0400
#define IMAGE_DLLCHARACTERISTICS_NO_BIND 0x0800
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER 0x1000
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER 0x2000
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000

struct IMAGE_OPTIONAL_HEADER64{
    WORD magic;
    BYTE majorLinkerVersion;
    BYTE minorLinkerVersion;
    DWORD sizeOfCode;
    DWORD sizeOfInitializedData;
    DWORD sizeOfUninitializedData;
    DWORD addressOfEntryPoint;
    DWORD baseOfCode;
    QWORD imageBase;
    QWORD sectionAlignment;
    QWORD fileAlignment;
    WORD majorOperatingSystemVersion;
    WORD minorOperatingSystemVersion;
    WORD majorImageVersion;
    WORD minorImageVersion;
    WORD majorSubsystemVersion;
    WORD minorSubsystemVersion;
    DWORD win32VersionValue;
    DWORD sizeOfImage;
    DWORD sizeOfHeaders;
    DWORD checksum;
    WORD subsystem;
    WORD dllCharacteristics;
    QWORD sizeOfStackReserve;
    QWORD sizeOfStackCommit;
    QWORD sizeOfHeapReserve;
    QWORD sizeOfHeapCommit;
    DWORD loaderFlags;
    DWORD numberOfRvaAndSizes;
    char* subsystemType;
    char** dllCharacteristicsList;
    struct IMAGE_DATA_DIRECTORY64 dataDirectory[16];
};

struct IMAGE_EXPORT_DIRECTORY64{
    DWORD characteristics;
    DWORD timeDateStamp;
    WORD majorVersion;
    WORD minorVersion;
    DWORD name;
    DWORD base;
    DWORD numberOfFunctions;
    DWORD numberOfNames;
    DWORD addressOfFunctions;
    DWORD addressOfNames;
    DWORD addressOfOrdinals;
};

struct IMAGE_IMPORT_BY_NAME64{
    WORD hint;
    BYTE name;
};

struct IMAGE_THUNK_DATA64{
    union{
        QWORD forwarderString;
        QWORD function;
        QWORD ordinal;
        QWORD addressOfData;
    } u1;
};

struct IMAGE_IMPORT_DESCRIPTOR64{
    union{
        DWORD Characteristics;
        struct IMAGE_THUNK_DATA32 OriginalFirstThunk;
    } u;
    DWORD timeDateStamp;
    DWORD forwarderChain;
    DWORD name;
    struct IMAGE_THUNK_DATA64 FirstThunk;
};

struct IMAGE_RESOURCE_DIRECTORY64{
    DWORD characteristics;
    DWORD timeDateStamp;
    WORD majorVersion;
    WORD minorVersion;
    WORD numberOfNamedEntries;
    WORD numberOfIdEntries; 
};

struct IMAGE_RESOURCE_DIRECTORY_ENTRY64{
    DWORD nameOffset;
    DWORD id;
};

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA64{
    DWORD dataRVA;
    DWORD size;
    DWORD codepage;
    DWORD reserved;
};

struct EXCEPTION_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
};

struct IMAGE_CERTIFICATE64{
	DWORD dwLength;
	WORD wRevision;
	WORD wCertificateType;
};

struct IMAGE_TLS_DIRECTORY64{
  QWORD startAddressOfRawData;
  QWORD endAddressOfRawData;
  QWORD addressOfIndex;
  QWORD addressOfCallBacks;
  DWORD sizeOfZeroFill;
  DWORD characteristics;
};

struct IMAGE_LOAD_CONFIG64{
    DWORD characteristics;
    DWORD timeDateStamp;
    WORD majorVersion;
    WORD minorVersion;
    DWORD globalFlagsClear;
    DWORD globalFlagsSet;
    DWORD criticalSectionDefaultTimeout;
    QWORD deCommitFreeBlockThreshold;
    QWORD deCommitTotalFreeThreshold;
    QWORD lockPrefixTable;
    QWORD maximumAllocationSize;
    QWORD virtualMemoryThreshold;
    QWORD processAffinityMask;
    DWORD processHeapFlags;
    WORD cSDVersion;
    WORD reserved;
    QWORD editList;
    QWORD securityCookie;
    QWORD sEHandlerTable;
    QWORD sEHandlerCount;
    QWORD guardCFCheckFunctionPointer;
    QWORD guardCFDispatchFunctionPointer;
    QWORD guardCFFunctionTable;
    QWORD guardCFFunctionCount;
    DWORD guardFlags;
    DWORD codeIntegrity[3];
    QWORD guardAddressTakenIatEntryTable;
    QWORD guardAddressTakenIatEntryCount;
    QWORD guardLongJumpTargetTable;
    QWORD guardLongJumpTargetCount;
};

struct ImgDelayDescr64{
    DWORD  grAttrs;
    DWORD  rvaDLLName;
    DWORD  rvaHmod;
    DWORD  rvaIAT;
    DWORD  rvaINT;
    DWORD  rvaBoundIAT;
    DWORD  rvaUnloadIAT;
    DWORD  dwTimeStamp;
};

//Function declarations
uint64_t convertRelativeAddressToDiskOffset64_t(uint64_t relativeAddress, uint16_t numberOfSections,  struct SECTION_HEADER* sectionHeader64);

void initializeOptionalHeader64(struct IMAGE_OPTIONAL_HEADER64* optionalHeader64);
void initializeExportDirectory64(struct IMAGE_EXPORT_DIRECTORY64* exports64);
void initializeImportDescriptor64(struct IMAGE_IMPORT_DESCRIPTOR64* importDescriptor);
void initializeCertificate64(size_t certificateCount, struct IMAGE_CERTIFICATE64* certificate64);
void initializeDebug64(size_t debugCount, struct IMAGE_DEBUG_DIRECTORY* debug64);
void initializeTLS64(struct IMAGE_TLS_DIRECTORY64* tls64);
void initializeLoadConfig64(struct IMAGE_LOAD_CONFIG64* loadConfig64);

void parsePE64(FILE* pefile, struct switchList* psList);
void parseOptionalHeader64(FILE* pefile, uint32_t elfanew, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64);
void parseExports64(FILE* pefile, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER* sectionHeader64, struct IMAGE_EXPORT_DIRECTORY64* exports64, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses);
void parseImports64(FILE* pefile, size_t numID, uint32_t diskOffset, struct IMAGE_IMPORT_DESCRIPTOR64** imports64);
void parseResources64(FILE* pefile);
void parseCertificate64(FILE* pefile, uint32_t diskOffset, size_t certificateCount, struct IMAGE_CERTIFICATE64* certificate64, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64);
void parseTLS64(FILE* pefile, uint32_t diskOffset, struct IMAGE_TLS_DIRECTORY64* tls64);
void parseLoadConfig64(FILE* pefile, uint32_t diskOffset, struct IMAGE_LOAD_CONFIG64* loadConfig64);

void consoleOutput64(struct IMAGE_DOS_HEADER* msDOSHeader, struct IMAGE_COFF_HEADER* coffHeader, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64, struct SECTION_HEADER* sectionHeader64);
void exportsConsoleOutput64(FILE* pefile, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64, struct IMAGE_EXPORT_DIRECTORY64* exports64, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses, uint16_t numberOfSections, struct SECTION_HEADER* sectionHeader64);
void importsConsoleOutput64(FILE* pefile, size_t numID, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER* sectionHeader64, struct IMAGE_IMPORT_DESCRIPTOR64** imports64);
void certificateConsoleOutput64(size_t certificateCount, struct IMAGE_CERTIFICATE64* certificate64);
void tlsConsoleOutput64(struct IMAGE_TLS_DIRECTORY64* tls64);
void loadConfigConsoleOutput64(struct IMAGE_LOAD_CONFIG64* loadConfig64);

#endif
