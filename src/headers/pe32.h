#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <curl/curl.h>

#ifndef PE32_H
#define PE32_H

//List of structs

struct switchList{
    bool fileSpecified;
    char* pathOfFileSpecified;
    bool directorySpecified;
    char* pathOfDirectorySpecified;
    bool exportResult;
    bool extractResources;
    bool extractStrings;
    bool vtLookup;
    char* vtAPIKey;
    bool urlLookup;
    bool shodanLookup;
    bool dnsLookup;
    bool computeHash;
    bool capabilityDetection;
};

struct GUID{
  DWORD Data1;
  WORD Data2;
  WORD Data3;
  BYTE Data4[8];
};

struct IMAGE_DATA_DIRECTORY32{
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

struct IMAGE_OPTIONAL_HEADER32{
    WORD magic;
    BYTE majorLinkerVersion;
    BYTE minorLinkerVersion;
    DWORD sizeOfCode;
    DWORD sizeOfInitializedData;
    DWORD sizeOfUninitializedData;
    DWORD addressOfEntryPoint;
    DWORD baseOfCode;
    DWORD baseOfData;
    DWORD imageBase;
    DWORD sectionAlignment;
    DWORD fileAlignment;
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
    DWORD sizeOfStackReserve;
    DWORD sizeOfStackCommit;
    DWORD sizeOfHeapReserve;
    DWORD sizeOfHeapCommit;
    DWORD loaderFlags;
    DWORD numberOfRvaAndSizes;
    char* subsystemType;
    char** dllCharacteristicsList;
    struct IMAGE_DATA_DIRECTORY32 dataDirectory[16];
};

struct IMAGE_EXPORT_DIRECTORY32{
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

struct IMPORT_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
};

struct IMAGE_IMPORT_BY_NAME32{
    WORD hint;
    BYTE name;
};

struct IMAGE_THUNK_DATA32{
    union{
        DWORD forwarderString;
        DWORD function;
        DWORD ordinal;
        DWORD addressOfData;
    } u1;
};

struct IMAGE_IMPORT_DESCRIPTOR32{
    union{
        DWORD Characteristics;
        struct IMAGE_THUNK_DATA32 OriginalFirstThunk;
    } u;
    DWORD timeDateStamp;
    DWORD forwarderChain;
    DWORD name;
    struct IMAGE_THUNK_DATA32 FirstThunk;
};

struct IMAGE_RESOURCE_DIRECTORY32{
    DWORD characteristics;
    DWORD timeDateStamp;
    WORD majorVersion;
    WORD minorVersion;
    WORD numberOfNamedEntries;
    WORD numberOfIdEntries; 
};

struct IMAGE_RESOURCE_DIRECTORY_ENTRY32{
    DWORD nameOffset;
    DWORD id;
};

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA32{
    DWORD dataRVA;
    DWORD size;
    DWORD codepage;
    DWORD reserved;
};

struct IMAGE_EXCEPTION32{
    DWORD startAddress;
    DWORD endAddress;
    DWORD unwindAddress;
};

struct IMAGE_CERTIFICATE32{
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

struct IMAGE_BASE_RELOCATION32{
  DWORD pageRVA;
  DWORD blockSize;
};

struct BASE_RELOCATION_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
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

struct IMAGE_DEBUG_DIRECTORY32{
  DWORD characteristics;
  DWORD timeDateStamp;
  WORD  majorVersion;
  WORD  minorVersion;
  DWORD type;
  DWORD sizeOfData;
  DWORD addressOfRawData;
  DWORD pointerToRawData;
};

struct CV_HEADER32{
  DWORD Signature;
  DWORD Offset;
};

struct CV_INFO_PDB20{
  struct CV_HEADER32 header;
  DWORD offset;
  DWORD signature;
  DWORD age;
  BYTE pdbFileName;
};

struct CV_INFO_PDB70{
  DWORD  cvSignature;
  struct GUID signature;
  DWORD age;
  BYTE pdbFileName;
};

struct IMAGE_TLS_DIRECTORY32{
  DWORD startAddressOfRawData;
  DWORD endAddressOfRawData;
  DWORD addressOfIndex;
  DWORD addressOfCallBacks;
  DWORD sizeOfZeroFill;
  DWORD characteristics;
};

struct IMAGE_LOAD_CONFIG32{
    DWORD characteristics;
    DWORD timeDateStamp;
    WORD majorVersion;
    WORD minorVersion;
    DWORD globalFlagsClear;
    DWORD globalFlagsSet;
    DWORD criticalSectionDefaultTimeout;
    DWORD deCommitFreeBlockThreshold;
    DWORD deCommitTotalFreeThreshold;
    DWORD lockPrefixTable;
    DWORD maximumAllocationSize;
    DWORD virtualMemoryThreshold;
    DWORD processAffinityMask;
    DWORD processHeapFlags;
    WORD cSDVersion;
    WORD reserved;
    DWORD editList;
    DWORD securityCookie;
    DWORD sEHandlerTable;
    DWORD sEHandlerCount;
    DWORD guardCFCheckFunctionPointer;
    DWORD guardCFDispatchFunctionPointer;
    DWORD guardCFFunctionTable;
    DWORD guardCFFunctionCount;
    DWORD guardFlags;
    DWORD codeIntegrity[3];
    DWORD guardAddressTakenIatEntryTable;
    DWORD guardAddressTakenIatEntryCount;
    DWORD guardLongJumpTargetTable;
    DWORD guardLongJumpTargetCount;
};

struct IMAGE_BOUND_IMPORT_DESCRIPTOR32{
    DWORD timestamp;
    WORD offsetModuleName;
    WORD numberOfModuleForwarderRefs;
};

struct IMAGE_BOUND_FORWARDER_REF32{
    DWORD timestamp;
    WORD offsetModuleName;
    WORD reserved;
};

struct ImgDelayDescr{
    DWORD  grAttrs;
    DWORD  rvaDLLName;
    DWORD  rvaHmod;
    DWORD  rvaIAT;
    DWORD  rvaINT;
    DWORD  rvaBoundIAT;
    DWORD  rvaUnloadIAT;
    DWORD  dwTimeStamp;
};

struct SECTION_HEADER32{
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
extern uint16_t convert_WORD_To_uint16_t(WORD structureValue);
extern uint32_t convert_DWORD_To_uint32_t(DWORD structureValue);
extern unsigned char hexdigit2int(unsigned char xd);
extern char* convert_uint64_t_ToString(uint64_t numericalValue, char* computedString);
extern uint32_t convertRelativeAddressToDiskOffset(uint32_t relativeAddress, uint16_t numberOfSections,  struct SECTION_HEADER32* sectionHeader32);

void initializeOptionalHeader32(struct IMAGE_OPTIONAL_HEADER32* optionalHeader32);
void initializeSectionHeader32(uint16_t numberOfSections, struct SECTION_HEADER32* sectionHeader32);
void initializeExportDirectory32(struct IMAGE_EXPORT_DIRECTORY32* exports32);
void initializeImportDescriptor32(struct IMAGE_IMPORT_DESCRIPTOR32* importDescriptor);
void initializeException32(size_t exceptionCount, struct IMAGE_EXCEPTION32* exception32);
void initializeCertificate32(size_t certificateCount, struct IMAGE_CERTIFICATE32* certificate32);
void initializeBaseReloc32(size_t baseRelocCount, struct IMAGE_BASE_RELOCATION32* baseReloc32);
void initializeDebug32(size_t debugCount, struct IMAGE_DEBUG_DIRECTORY32* debug32);
void initializeTLS32(struct IMAGE_TLS_DIRECTORY32* tls32);
void initializeLoadConfig32(struct IMAGE_LOAD_CONFIG32* loadConfig32);
void initializeBoundImport32(uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR32* bounds32);

void parsePE32(FILE* pefile, struct switchList* psList);
void parseOptionalHeader32(FILE* pefile, uint32_t elfanew, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32);
void parseSectionHeaders32(FILE* pefile, uint16_t numberOfSections, uint32_t memoryOffset, struct SECTION_HEADER32* sectionHeader32);
void parseExports32(FILE* pefile, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER32* sectionHeader32, struct IMAGE_EXPORT_DIRECTORY32* exports32, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses);
void parseImports32(FILE* pefile, size_t numID, uint32_t diskOffset, struct IMAGE_IMPORT_DESCRIPTOR32** imports32);
void parseResources32(FILE* pefile);
void parseException32(FILE* pefile, uint32_t diskOffset, size_t exceptionCount, struct IMAGE_EXCEPTION32* exception32);
void parseCertificate32(FILE* pefile, uint32_t diskOffset, size_t certificateCount, struct IMAGE_CERTIFICATE32* certificate32, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32);
void parseBaseReloc32(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION32* baseReloc32);
void parseDebug32(FILE* pefile, size_t debugCount, uint32_t diskOffset, struct IMAGE_DEBUG_DIRECTORY32* debug32);
void parseTLS32(FILE* pefile, uint32_t diskOffset, struct IMAGE_TLS_DIRECTORY32* tls32);
void parseLoadConfig32(FILE* pefile, uint32_t diskOffset, struct IMAGE_LOAD_CONFIG32* loadConfig32);
void parseBoundImport32(FILE* pefile, uint32_t diskOffset, uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR32* bounds32);

void consoleOutput32(struct IMAGE_DOS_HEADER* msDOSHeader, struct IMAGE_COFF_HEADER* coffHeader, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32, struct SECTION_HEADER32* sectionHeader32);
void exportsConsoleOutput32(FILE* pefile, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32, struct IMAGE_EXPORT_DIRECTORY32* exports32, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses, uint16_t numberOfSections, struct SECTION_HEADER32* sectionHeader32);
void importsConsoleOutput32(FILE* pefile, size_t numID, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER32* sectionHeader32, struct IMAGE_IMPORT_DESCRIPTOR32** imports32);
void exceptionConsoleOutput32(size_t exceptionCount, struct IMAGE_EXCEPTION32* exception32);
void certificateConsoleOutput32(size_t certificateCount, struct IMAGE_CERTIFICATE32* certificate32);
void baseRelocConsoleOutput32(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION32* baseReloc32);
void debugConsoleOutput32(FILE* pefile, size_t debugCount, struct IMAGE_DEBUG_DIRECTORY32* debug32, struct SECTION_HEADER32* sectionHeader32);
void tlsConsoleOutput32(struct IMAGE_TLS_DIRECTORY32* tls32);
void loadConfigConsoleOutput32(struct IMAGE_LOAD_CONFIG32* loadConfig32);
void boundsConsoleOutput32(uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR32* bounds32);

#endif
