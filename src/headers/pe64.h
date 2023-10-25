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

struct IMAGE_EXCEPTION64{
    DWORD startAddress;
    DWORD endAddress;
    DWORD unwindAddress;
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

//Base Relocation Types
#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGH 1
#define IMAGE_REL_BASED_LOW 2
#define IMAGE_REL_BASED_HIGHLOW 3
#define IMAGE_REL_BASED_HIGHADJ 4
#define IMAGE_REL_BASED_MIPS_JMPADDR 5
#define IMAGE_REL_BASED_ARM_MOV32 5
#define IMAGE_REL_BASED_RISCV_HIGH20 5
#define IMAGE_REL_BASED_THUMB_MOV32 7
#define IMAGE_REL_BASED_RISCV_LOW12I 7
#define IMAGE_REL_BASED_RISCV_LOW12S 8
#define IMAGE_REL_BASED_LOONGARCH32_MARK_LA 8
#define IMAGE_REL_BASED_LOONGARCH64_MARK_LA 8
#define IMAGE_REL_BASED_MIPS_JMPADDR16 9
#define IMAGE_REL_BASED_DIR64 10

struct IMAGE_BASE_RELOCATION64{
  DWORD pageRVA;
  DWORD blockSize;
};

// Debug Type
#define IMAGE_DEBUG_TYPE_UNKNOWN          0
#define IMAGE_DEBUG_TYPE_COFF             1
#define IMAGE_DEBUG_TYPE_CODEVIEW         2
#define IMAGE_DEBUG_TYPE_FPO              3
#define IMAGE_DEBUG_TYPE_MISC             4
#define IMAGE_DEBUG_TYPE_EXCEPTION        5
#define IMAGE_DEBUG_TYPE_FIXUP            6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC      7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    8
#define IMAGE_DEBUG_TYPE_BORLAND          9
#define IMAGE_DEBUG_TYPE_RESERVED10       10
#define IMAGE_DEBUG_TYPE_CLSID            11
#define IMAGE_DEBUG_TYPE_VC_FEATURE       12
#define IMAGE_DEBUG_TYPE_POGO             13
#define IMAGE_DEBUG_TYPE_ILTCG            14
#define IMAGE_DEBUG_TYPE_MPX              15
#define IMAGE_DEBUG_TYPE_REPRO            16

struct IMAGE_DEBUG_DIRECTORY64{
  DWORD characteristics;
  DWORD timeDateStamp;
  WORD  majorVersion;
  WORD  minorVersion;
  DWORD type;
  DWORD sizeOfData;
  DWORD addressOfRawData;
  DWORD pointerToRawData;
};

struct CV_HEADER64{
  DWORD Signature;
  DWORD Offset;
};

struct CV_INFO_PDB20_64{
  struct CV_HEADER64 header;
  DWORD offset;
  DWORD signature;
  DWORD age;
  BYTE pdbFileName;
};

struct CV_INFO_PDB70_64{
  DWORD  cvSignature;
  struct GUID signature;
  DWORD age;
  BYTE pdbFileName;
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

struct IMAGE_BOUND_IMPORT_DESCRIPTOR64{
    DWORD timestamp;
    WORD offsetModuleName;
    WORD numberOfModuleForwarderRefs;
};

struct IMAGE_BOUND_FORWARDER_REF64{
    DWORD timestamp;
    WORD offsetModuleName;
    WORD reserved;
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

struct SECTION_HEADER64{
    QWORD name;
    DWORD virtualSize;
    DWORD virtualAddress;
    DWORD sizeOfRawData;
    DWORD pointerToRawData;
    DWORD pointerToRelocations;
    DWORD pointerToLineNumbers;
    WORD numberOfRelocations;
    WORD numberOfLineNumbers;
    DWORD characteristics;
};

//Function declarations
uint32_t convertRelativeAddressToDiskOffset64(uint32_t relativeAddress, uint16_t numberOfSections,  struct SECTION_HEADER64* sectionHeader64);
uint64_t convertRelativeAddressToDiskOffset64_t(uint64_t relativeAddress, uint16_t numberOfSections,  struct SECTION_HEADER64* sectionHeader64);

void initializeOptionalHeader64(struct IMAGE_OPTIONAL_HEADER64* optionalHeader64);
void initializeSectionHeader64(uint16_t numberOfSections, struct SECTION_HEADER64* sectionHeader64);
void initializeExportDirectory64(struct IMAGE_EXPORT_DIRECTORY64* exports64);
void initializeImportDescriptor64(struct IMAGE_IMPORT_DESCRIPTOR64* importDescriptor);
void initializeException64(size_t exceptionCount, struct IMAGE_EXCEPTION64* exception64);
void initializeCertificate64(size_t certificateCount, struct IMAGE_CERTIFICATE64* certificate64);
void initializeBaseReloc64(size_t baseRelocCount, struct IMAGE_BASE_RELOCATION64* baseReloc64);
void initializeDebug64(size_t debugCount, struct IMAGE_DEBUG_DIRECTORY64* debug64);
void initializeTLS64(struct IMAGE_TLS_DIRECTORY64* tls64);
void initializeLoadConfig64(struct IMAGE_LOAD_CONFIG64* loadConfig64);
void initializeBoundImport64(uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR64* bounds64);

void parsePE64(FILE* pefile, struct switchList* psList);
void parseOptionalHeader64(FILE* pefile, uint32_t elfanew, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64);
void parseSectionHeaders64(FILE* pefile, uint16_t numberOfSections, uint32_t memoryOffset, struct SECTION_HEADER64* sectionHeader64);
void parseExports64(FILE* pefile, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER64* sectionHeader64, struct IMAGE_EXPORT_DIRECTORY64* exports64, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses);
void parseImports64(FILE* pefile, size_t numID, uint32_t diskOffset, struct IMAGE_IMPORT_DESCRIPTOR64** imports64);
void parseResources64(FILE* pefile);
void parseException64(FILE* pefile, uint32_t diskOffset, size_t exceptionCount, struct IMAGE_EXCEPTION64* exception64);
void parseCertificate64(FILE* pefile, uint32_t diskOffset, size_t certificateCount, struct IMAGE_CERTIFICATE64* certificate64, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64);
void parseBaseReloc64(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION64* baseReloc64);
void parseDebug64(FILE* pefile, size_t debugCount, uint32_t diskOffset, struct IMAGE_DEBUG_DIRECTORY64* debug64);
void parseTLS64(FILE* pefile, uint32_t diskOffset, struct IMAGE_TLS_DIRECTORY64* tls64);
void parseLoadConfig64(FILE* pefile, uint32_t diskOffset, struct IMAGE_LOAD_CONFIG64* loadConfig64);
void parseBoundImport64(FILE* pefile, uint32_t diskOffset, uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR64* bounds64);

void consoleOutput64(struct IMAGE_DOS_HEADER* msDOSHeader, struct IMAGE_COFF_HEADER* coffHeader, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64, struct SECTION_HEADER64* sectionHeader64);
void exportsConsoleOutput64(FILE* pefile, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64, struct IMAGE_EXPORT_DIRECTORY64* exports64, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses, uint16_t numberOfSections, struct SECTION_HEADER64* sectionHeader64);
void importsConsoleOutput64(FILE* pefile, size_t numID, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER64* sectionHeader64, struct IMAGE_IMPORT_DESCRIPTOR64** imports64);
void exceptionConsoleOutput64(size_t exceptionCount, struct IMAGE_EXCEPTION64* exception64);
void certificateConsoleOutput64(size_t certificateCount, struct IMAGE_CERTIFICATE64* certificate64);
void baseRelocConsoleOutput64(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION64* baseReloc64);
void debugConsoleOutput64(FILE* pefile, size_t debugCount, struct IMAGE_DEBUG_DIRECTORY64* debug64, struct SECTION_HEADER64* sectionHeader64);
void tlsConsoleOutput64(struct IMAGE_TLS_DIRECTORY64* tls64);
void loadConfigConsoleOutput64(struct IMAGE_LOAD_CONFIG64* loadConfig64);
void boundsConsoleOutput64(uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR64* bounds64);

#endif
