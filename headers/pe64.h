#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifndef PE64_H
#define PE64_H

//List of structs

struct IMAGE_DOS_HEADER64{
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    DWORD e_lfanew;
};

struct IMAGE_COFF_HEADER64{
    DWORD peSignature;
    WORD machine;
    WORD numberOfSections;
    DWORD timeDateStamp;
    DWORD pointerToSymbolTable;
    DWORD numberOfSymbols;
    WORD sizeOfOptionalHeader;
    WORD characteristics;
    char* machineArchitecture;
    char** characteristicsList;
};

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

struct EXPORT_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
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

struct IMPORT_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
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


struct RESOURCE_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
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

struct CERTIFICATE_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
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

struct BASE_RELOCATION_DATA_DIRECTORY64{
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

struct DEBUG_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
};

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

struct ARCHITECTURE_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
};

struct GLOBAL_PTR_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
};

struct IMAGE_TLS_DIRECTORY64{
  QWORD startAddressOfRawData;
  QWORD endAddressOfRawData;
  QWORD addressOfIndex;
  QWORD addressOfCallBacks;
  DWORD sizeOfZeroFill;
  DWORD characteristics;
};


struct TLS_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
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

struct LOAD_CONFIG_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
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

struct BOUND_IMPORT_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
};

struct IAT_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
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

struct DELAY_IMPORT_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
};

struct CLR_RUNTIME_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
};

struct RESERVED_DATA_DIRECTORY64{
    DWORD virtualAddress;
    DWORD size;
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

void parseMSDOSHeader64(FILE* pefile, struct IMAGE_DOS_HEADER64* msDOSHeader64);
void parseCoffHeader64(FILE* pefile, uint32_t elfanew, struct IMAGE_COFF_HEADER64* coffHeader64);
void parseOptionalHeader64(FILE* pefile, uint32_t elfanew, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64);
void parseSectionHeaders64(FILE* pefile, uint16_t numberOfSections, uint32_t memoryOffset, struct SECTION_HEADER64* sectionHeader64);
void parseExports64(FILE* pefile, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER64* sectionHeader64, struct IMAGE_EXPORT_DIRECTORY64* exports64, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses);
void parseImports64(FILE* pefile, size_t numID, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER64* sectionHeader64, struct IMAGE_IMPORT_DESCRIPTOR64** imports64);
void parseResources64(FILE* pefile);
void parseException64(FILE* pefile, uint32_t diskOffset, size_t exceptionCount, struct IMAGE_EXCEPTION64* exception64);
void parseCertificate64(FILE* pefile, uint32_t diskOffset, size_t certificateCount, struct IMAGE_CERTIFICATE64* certificate64, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64);
void parseBaseReloc64(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION64* baseReloc64);
void parseDebug64(FILE* pefile, size_t debugCount, uint32_t diskOffset, struct IMAGE_DEBUG_DIRECTORY64* debug64);
void parseArch64();
void parseTLS64(FILE* pefile, uint32_t diskOffset, struct IMAGE_TLS_DIRECTORY64* tls64);
void parseLoadConfig64(FILE* pefile, uint32_t diskOffset, struct IMAGE_LOAD_CONFIG64* loadConfig64);
void parseBoundImport64(FILE* pefile, uint32_t diskOffset, uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR64* bounds64);
void parseIAT64();
void parseDelayImport64();
void parseRuntime64();

void consoleOutput64(struct IMAGE_DOS_HEADER64* msDOSHeader64, struct IMAGE_COFF_HEADER64* coffHeader64, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64, struct SECTION_HEADER64* sectionHeader64);
void exportsConsoleOutput64(FILE* pefile, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64, struct IMAGE_EXPORT_DIRECTORY64* exports64, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses, uint16_t numberOfSections, struct SECTION_HEADER64* sectionHeader64);
void importsConsoleOutput64(FILE* pefile, size_t numID, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER64* sectionHeader64, struct IMAGE_IMPORT_DESCRIPTOR64** imports64);
void exceptionConsoleOutput64(FILE* pefile, uint32_t diskOffset, size_t exceptionCount, struct IMAGE_EXCEPTION64* exception64);
void certificateConsoleOutput64(FILE* pefile, size_t certificateCount, struct IMAGE_CERTIFICATE64* certificate64);
void baseRelocConsoleOutput64(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION64* baseReloc64);
void debugConsoleOutput64(FILE* pefile, size_t debugCount, uint32_t diskOffset, struct IMAGE_DEBUG_DIRECTORY64* debug64, struct SECTION_HEADER64* sectionHeader64);
void loadConfigConsoleOutput64(FILE* pefile, struct IMAGE_LOAD_CONFIG64* loadConfig64);
void boundsConsoleOutput64(FILE* pefile, uint32_t diskOffset, uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR64* bounds64);


uint32_t convertRelativeAddressToDiskOffset64(uint32_t relativeAddress, uint16_t numberOfSections,  struct SECTION_HEADER64* sectionHeader64){
    size_t i=0;

    for(i=0; i<numberOfSections; i++){
        uint32_t sectionHeaderVirtualAddress = (((sectionHeader64[i].virtualAddress&255)&15)*16777216) + (((sectionHeader64[i].virtualAddress&255)>>4)*268435456) + ((((sectionHeader64[i].virtualAddress>>8)&255)&15)*65536) + ((((sectionHeader64[i].virtualAddress>>8)&255)>>4)*1048576) + (((sectionHeader64[i].virtualAddress>>16)&15)*256) + ((((sectionHeader64[i].virtualAddress>>16)&255)>>4)*4096) + (((sectionHeader64[i].virtualAddress>>24)&15)*1) + (((sectionHeader64[i].virtualAddress>>24)>>4)*16);
        uint32_t sectionHeaderPointerToRawData = (((sectionHeader64[i].pointerToRawData&255)&15)*16777216) + (((sectionHeader64[i].pointerToRawData&255)>>4)*268435456) + ((((sectionHeader64[i].pointerToRawData>>8)&255)&15)*65536) + ((((sectionHeader64[i].pointerToRawData>>8)&255)>>4)*1048576) + (((sectionHeader64[i].pointerToRawData>>16)&15)*256) + ((((sectionHeader64[i].pointerToRawData>>16)&255)>>4)*4096) + (((sectionHeader64[i].pointerToRawData>>24)&15)*1) + (((sectionHeader64[i].pointerToRawData>>24)>>4)*16);
        uint32_t sectionHeaderSizeOfRawData = (((sectionHeader64[i].sizeOfRawData&255)&15)*16777216) + (((sectionHeader64[i].sizeOfRawData&255)>>4)*268435456) + ((((sectionHeader64[i].sizeOfRawData>>8)&255)&15)*65536) + ((((sectionHeader64[i].sizeOfRawData>>8)&255)>>4)*1048576) + (((sectionHeader64[i].sizeOfRawData>>16)&15)*256) + ((((sectionHeader64[i].sizeOfRawData>>16)&255)>>4)*4096) + (((sectionHeader64[i].sizeOfRawData>>24)&15)*1) + (((sectionHeader64[i].sizeOfRawData>>24)>>4)*16);
        
        if((relativeAddress >= sectionHeaderVirtualAddress) && (relativeAddress <= (sectionHeaderVirtualAddress + sectionHeaderSizeOfRawData))){
            return (uint32_t)(sectionHeaderPointerToRawData + relativeAddress - sectionHeaderVirtualAddress);
        }
    }

    return 0;
}

uint64_t convertRelativeAddressToDiskOffset64_t(uint64_t relativeAddress, uint16_t numberOfSections,  struct SECTION_HEADER64* sectionHeader64){

size_t i=0;

    for(i=0; i<numberOfSections; i++){
        uint64_t sectionHeaderVirtualAddress = (((sectionHeader64[i].virtualAddress&255)&15)*16777216) + (((sectionHeader64[i].virtualAddress&255)>>4)*268435456) + ((((sectionHeader64[i].virtualAddress>>8)&255)&15)*65536) + ((((sectionHeader64[i].virtualAddress>>8)&255)>>4)*1048576) + (((sectionHeader64[i].virtualAddress>>16)&15)*256) + ((((sectionHeader64[i].virtualAddress>>16)&255)>>4)*4096) + (((sectionHeader64[i].virtualAddress>>24)&15)*1) + (((sectionHeader64[i].virtualAddress>>24)>>4)*16);
        uint64_t sectionHeaderPointerToRawData = (((sectionHeader64[i].pointerToRawData&255)&15)*16777216) + (((sectionHeader64[i].pointerToRawData&255)>>4)*268435456) + ((((sectionHeader64[i].pointerToRawData>>8)&255)&15)*65536) + ((((sectionHeader64[i].pointerToRawData>>8)&255)>>4)*1048576) + (((sectionHeader64[i].pointerToRawData>>16)&15)*256) + ((((sectionHeader64[i].pointerToRawData>>16)&255)>>4)*4096) + (((sectionHeader64[i].pointerToRawData>>24)&15)*1) + (((sectionHeader64[i].pointerToRawData>>24)>>4)*16);
        uint64_t sectionHeaderSizeOfRawData = (((sectionHeader64[i].sizeOfRawData&255)&15)*16777216) + (((sectionHeader64[i].sizeOfRawData&255)>>4)*268435456) + ((((sectionHeader64[i].sizeOfRawData>>8)&255)&15)*65536) + ((((sectionHeader64[i].sizeOfRawData>>8)&255)>>4)*1048576) + (((sectionHeader64[i].sizeOfRawData>>16)&15)*256) + ((((sectionHeader64[i].sizeOfRawData>>16)&255)>>4)*4096) + (((sectionHeader64[i].sizeOfRawData>>24)&15)*1) + (((sectionHeader64[i].sizeOfRawData>>24)>>4)*16);
        
        if((relativeAddress >= sectionHeaderVirtualAddress) && (relativeAddress <= (sectionHeaderVirtualAddress + sectionHeaderSizeOfRawData))){
            return (uint64_t)(sectionHeaderPointerToRawData + relativeAddress - sectionHeaderVirtualAddress);
        }
    }

    return 0;

}

void parseMSDOSHeader64(FILE* pefile, struct IMAGE_DOS_HEADER64* msDOSHeader64){
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    size_t j = 0;

    msDOSHeader64->e_magic = readWord(pefile, 0x00, WORD_Buffer);
    msDOSHeader64->e_cblp = readWord(pefile, 0x02, WORD_Buffer);
    msDOSHeader64->e_cp = readWord(pefile, 0x04, WORD_Buffer);
    msDOSHeader64->e_crlc = readWord(pefile, 0x06, WORD_Buffer);
    msDOSHeader64->e_cparhdr = readWord(pefile, 0x08, WORD_Buffer);
    msDOSHeader64->e_minalloc = readWord(pefile, 0x0A, WORD_Buffer);
    msDOSHeader64->e_maxalloc = readWord(pefile, 0x0C, WORD_Buffer);
    msDOSHeader64->e_ss = readWord(pefile, 0x0E, WORD_Buffer);
    msDOSHeader64->e_sp = readWord(pefile, 0x10, WORD_Buffer);
    msDOSHeader64->e_csum = readWord(pefile, 0x12, WORD_Buffer);
    msDOSHeader64->e_ip = readWord(pefile, 0x14, WORD_Buffer);
    msDOSHeader64->e_cs = readWord(pefile, 0x16, WORD_Buffer);
    msDOSHeader64->e_lfarlc = readWord(pefile, 0x18, WORD_Buffer);
    msDOSHeader64->e_ovno = readWord(pefile, 0x1A, WORD_Buffer);
    
    for(size_t i=0x1C;i<0x24;i+=0x02){
        msDOSHeader64->e_res[j++] = readWord(pefile, i, WORD_Buffer);
    }

    msDOSHeader64->e_oemid = readWord(pefile, 0x24, WORD_Buffer);
    
    j=0;
    for(size_t i=0x26;i<0x3C;i+=0x02){
        msDOSHeader64->e_res2[j++] = readWord(pefile, i, WORD_Buffer);
    }

    msDOSHeader64->e_lfanew = readDWord(pefile, 0x3C, DWORD_Buffer);

    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseCoffHeader64(FILE* file, uint32_t elfanew, struct IMAGE_COFF_HEADER64* coffHeader64){
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));

    coffHeader64->peSignature = readDWord(file, elfanew, DWORD_Buffer);
    coffHeader64->machine = readWord(file, elfanew+4, WORD_Buffer);
    coffHeader64->numberOfSections = readWord(file, elfanew+6, WORD_Buffer);
    coffHeader64->timeDateStamp = readDWord(file, elfanew+8, DWORD_Buffer);
    coffHeader64->pointerToSymbolTable = readDWord(file, elfanew+12, DWORD_Buffer);
    coffHeader64->numberOfSymbols = readDWord(file, elfanew+16, DWORD_Buffer);
    coffHeader64->sizeOfOptionalHeader = readWord(file, elfanew+20, WORD_Buffer);
    coffHeader64->characteristics = readWord(file, elfanew+22, WORD_Buffer);

    switch(reverse_endianess_uint16_t(coffHeader64->machine)){
        case 0x0:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_UNKNOWN", 27);
            break;
        case 0x1d3:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_AM33", 24);
            break;
        case 0x8664:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_AMD64", 25);
            break;
        case 0x1c0:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_ARM", 24);
            break;
        case 0xaa64:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_ARM64", 25);
            break;
        case 0x1c4:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_ARMNT", 25);
            break;
        case 0xebc:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_EBC", 23);
            break;
        case 0x14c:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_I386", 24);
            break;
        case 0x200:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_IA64", 24);
            break;
        case 0x6232:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_LOONGARCH32", 31);
            break;
        case 0x6264:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_LOONGARCH64", 31);
            break;
        case 0x9041:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_M32R", 24);
            break;
        case 0x266:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_MIPS16", 26);
            break;
        case 0x366:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_MIPSFPU", 27);
            break;
        case 0x1f0:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_POWERPC", 27);
            break;
        case 0x1f1:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_POWERPCFP", 29);
            break;
        case 0x166:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_R4000", 25);
            break;
        case 0x5032:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_RISCV32", 27);
            break;
        case 0x5064:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_RISCV64", 27);
            break;
        case 0x5128:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_RISCV128", 28);
            break;
        case 0x1a2:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_SH3", 23);
            break;
        case 0x1a3:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_SH3DSP", 26);
            break;
        case 0x1a6:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_SH4", 23);
            break;
        case 0x1a8:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_SH5", 23);
            break;
        case 0x1c2:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_THUMB", 25);
            break;
        case 0x169:
            memcpy(coffHeader64->machineArchitecture, "IMAGE_FILE_MACHINE_WCEMIPSV2", 29);
            break;
        default:
            memcpy(coffHeader64->machineArchitecture, "UNDEFINED_ARCHITECTURE_ANOMALY", 31);
            break;
    }

    int imageFileCharacteristics[16] = {1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768};
    int* savedCharacteristics = calloc(16, sizeof(int));
    size_t j=0;
    uint16_t characteristics = reverse_endianess_uint16_t(coffHeader64->characteristics);

    for(int i=15;i>=0;i--){
        if(((characteristics - imageFileCharacteristics[i]) >= 0) && (characteristics!=0)){
            savedCharacteristics[j++] = imageFileCharacteristics[i];
            characteristics -= imageFileCharacteristics[i];
        }
    }
    
    for(size_t i=0;i<j;i++){
        switch(savedCharacteristics[i]){
            case 1:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_RELOCS_STRIPPED", 27);
                break;
            case 2:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_EXECUTABLE_IMAGE", 28);
                break;
            case 4:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_LINE_NUMS_STRIPPED", 29);
                break;
            case 8:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_LOCAL_SYMS_STRIPPED", 31);
                break;
            case 16:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_AGGRESSIVE_WS_TRIM", 30);
                break;
            case 32:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_LARGE_ADDRESS_AWARE", 31);
                break;
            case 64:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_FUTURE_USE", 22);
                break;
            case 128:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_BYTES_REVERSED_LO", 29);
                break;
            case 256:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_32BIT_MACHINE", 25);
                break;
            case 512:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_DEBUG_STRIPPED", 26);
                break;
            case 1024:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_REMOVABLE_RUN_", 26);
                break;
            case 2048:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_NET_RUN_FROM_SWAP", 29);
                break;
            case 4096:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_SYSTEM", 18);
                break;
            case 8192:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_DLL", 15);
                break;
            case 16384:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_UP_SYSTEM_ONLY", 26);
                break;
            case 32768:
                memcpy(coffHeader64->characteristicsList[i], "IMAGE_FILE_BYTES_REVERSED_HI", 29);
                break;
            default:
                memcpy(coffHeader64->characteristicsList[i], "UNKNOWN_CHARACTERISTICS_ANOMALY", 32);
                break;
        }
    }

    free(savedCharacteristics);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseOptionalHeader64(FILE* pefile, uint32_t elfanew, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64){
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));

    optionalHeader64->magic = readWord(pefile, elfanew+24, WORD_Buffer);
    optionalHeader64->majorLinkerVersion = readByte(pefile, elfanew+26, BYTE_Buffer);
    optionalHeader64->minorLinkerVersion = readByte(pefile, elfanew+27, BYTE_Buffer);
    optionalHeader64->sizeOfCode = readDWord(pefile, elfanew+28, DWORD_Buffer);
    optionalHeader64->sizeOfInitializedData = readDWord(pefile, elfanew+32, DWORD_Buffer);
    optionalHeader64->sizeOfUninitializedData = readDWord(pefile, elfanew+36, DWORD_Buffer);
    optionalHeader64->addressOfEntryPoint = readDWord(pefile, elfanew+40, DWORD_Buffer);
    optionalHeader64->baseOfCode = readDWord(pefile, elfanew+44, DWORD_Buffer);
    optionalHeader64->imageBase = readQWord(pefile, elfanew+48, QWORD_Buffer);
    optionalHeader64->sectionAlignment = readDWord(pefile, elfanew+56, DWORD_Buffer);
    optionalHeader64->fileAlignment = readDWord(pefile, elfanew+60, DWORD_Buffer);
    optionalHeader64->majorOperatingSystemVersion = readWord(pefile, elfanew+64, WORD_Buffer);
    optionalHeader64->minorOperatingSystemVersion = readWord(pefile, elfanew+66, WORD_Buffer);
    optionalHeader64->majorImageVersion = readWord(pefile, elfanew+68, WORD_Buffer);
    optionalHeader64->minorImageVersion = readWord(pefile, elfanew+70, WORD_Buffer);
    optionalHeader64->majorSubsystemVersion = readWord(pefile, elfanew+72, WORD_Buffer);
    optionalHeader64->minorSubsystemVersion = readWord(pefile, elfanew+74, WORD_Buffer);
    optionalHeader64->win32VersionValue = readDWord(pefile, elfanew+76, DWORD_Buffer);
    optionalHeader64->sizeOfImage = readDWord(pefile, elfanew+80, DWORD_Buffer);
    optionalHeader64->sizeOfHeaders = readDWord(pefile, elfanew+84, DWORD_Buffer);
    optionalHeader64->checksum = readDWord(pefile, elfanew+88, DWORD_Buffer);
    optionalHeader64->subsystem = readWord(pefile, elfanew+92, WORD_Buffer);
    optionalHeader64->dllCharacteristics = readWord(pefile, elfanew+94, WORD_Buffer);
    
    optionalHeader64->sizeOfStackReserve = readQWord(pefile, elfanew+96, QWORD_Buffer);
    optionalHeader64->sizeOfStackCommit = readQWord(pefile, elfanew+104, QWORD_Buffer);
    optionalHeader64->sizeOfHeapReserve = readQWord(pefile, elfanew+112, QWORD_Buffer);
    optionalHeader64->sizeOfHeapCommit = readQWord(pefile, elfanew+120, QWORD_Buffer);
    optionalHeader64->loaderFlags = readDWord(pefile, elfanew+128, DWORD_Buffer);
    optionalHeader64->numberOfRvaAndSizes = readDWord(pefile, elfanew+132, DWORD_Buffer);

    size_t j=0;
    size_t maxDirectories = reverse_endianess_uint32_t(optionalHeader64->numberOfRvaAndSizes);
    for(size_t i=0;i<maxDirectories;i++){
        optionalHeader64->dataDirectory[i].virtualAddress = readDWord(pefile, elfanew+136+j, DWORD_Buffer);
        j+=4;
        optionalHeader64->dataDirectory[i].size = readDWord(pefile, elfanew+136+j, DWORD_Buffer);
        j+=4;
    }

    switch(reverse_endianess_uint16_t(optionalHeader64->subsystem)){
        case 0:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_UNKNOWN", 24);
            break;
        case 1:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_NATIVE", 23);
            break;
        case 2:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_WINDOWS_GUI", 28);
            break;
        case 3:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_WINDOWS_CUI", 28);
            break;
        case 5:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_OS2_CUI", 24);
            break;
        case 7:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_POSIX_CUI", 26);
            break;
        case 8:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_NATIVE_WINDOWS", 31);
            break;
        case 9:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", 31);
            break;
        case 10:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_EFI_APPLICATION", 32);
            break;
        case 11:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", 40);
            break;
        case 12:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", 35);
            break;
        case 13:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_EFI_ROM", 24);
            break;
        case 14:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_XBOX", 21);
            break;
        case 16:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", 41);
            break;
        default:
            memcpy(optionalHeader64->subsystemType, "UNDEFINED_IMAGE_SUBSYSTEM_ANOMALY", 34);
            break;
    }

    int imageFileCharacteristics[16] = {1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768};
    int* savedCharacteristics = calloc(16, sizeof(int));
    j=0;
    uint16_t dllCharacteristics = reverse_endianess_uint16_t(optionalHeader64->dllCharacteristics);

    for(int i=15;i>=0;i--){
        if(((dllCharacteristics - imageFileCharacteristics[i]) >= 0) && (dllCharacteristics!=0)){
            savedCharacteristics[j++] = imageFileCharacteristics[i];
            dllCharacteristics -= imageFileCharacteristics[i];
        }
    }

    for(size_t i=0;i<j;i++){
        switch(savedCharacteristics[i]){
            case 32:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", 41);
                break;
            case 64:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", 38);
                break;
            case 128:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", 41);
                break;
            case 256:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_NX_COMPAT", 35);
                break;
            case 512:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", 38);
                break;
            case 1024:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_NO_SEH", 32);
                break;
            case 2048:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_NO_BIND", 33);
                break;
            case 4096:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_APPCONTAINER", 38);
                break;
            case 8192:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", 36);
                break;
            case 16384:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_GUARD_CF", 34);
                break;
            case 32768:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", 47);
                break;
            default:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "UNKNOWN_DLL_CHARACTERISTICS_ANOMALY", 36);
                break;
        }
    }

    free(savedCharacteristics);
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void parseSectionHeaders64(FILE* pefile, uint16_t numberOfSections, uint32_t memoryOffset, struct SECTION_HEADER64* sectionHeader64){

    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));

    for(size_t i=0; i<numberOfSections; i++){
        sectionHeader64[i].name = readQWord(pefile, memoryOffset+i*40, QWORD_Buffer);
        sectionHeader64[i].virtualSize = readDWord(pefile, memoryOffset+i*40+8, DWORD_Buffer);
        sectionHeader64[i].virtualAddress = readDWord(pefile, memoryOffset+i*40+12, DWORD_Buffer);
        sectionHeader64[i].sizeOfRawData = readDWord(pefile, memoryOffset+i*40+16, DWORD_Buffer);
        sectionHeader64[i].pointerToRawData = readDWord(pefile, memoryOffset+i*40+20, DWORD_Buffer);
        sectionHeader64[i].pointerToRelocations = readDWord(pefile, memoryOffset+i*40+24, DWORD_Buffer);
        sectionHeader64[i].pointerToLineNumbers = readDWord(pefile, memoryOffset+i*40+28, DWORD_Buffer);
        sectionHeader64[i].numberOfRelocations = readWord(pefile, memoryOffset+i*40+32, WORD_Buffer);
        sectionHeader64[i].numberOfLineNumbers = readWord(pefile, memoryOffset+i*40+34, WORD_Buffer);
        sectionHeader64[i].characteristics = readDWord(pefile, memoryOffset+i*40+36, DWORD_Buffer);
    }
    
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void parseExports64(FILE* pefile, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER64* sectionHeader64, struct IMAGE_EXPORT_DIRECTORY64* exports64, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses){
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));
    
    
    exports64->characteristics = readDWord(pefile, diskOffset, DWORD_Buffer);
    exports64->timeDateStamp = readDWord(pefile, diskOffset+4, DWORD_Buffer);
    exports64->majorVersion = readWord(pefile, diskOffset+8, WORD_Buffer);
    exports64->minorVersion = readWord(pefile, diskOffset+10, WORD_Buffer);
    exports64->name = readDWord(pefile, diskOffset+12, DWORD_Buffer);
    exports64->base = readDWord(pefile, diskOffset+16, DWORD_Buffer);
    exports64->numberOfFunctions = readDWord(pefile, diskOffset+20, DWORD_Buffer);
    exports64->numberOfNames = readDWord(pefile, diskOffset+24, DWORD_Buffer);
    exports64->addressOfFunctions = readDWord(pefile, diskOffset+28, DWORD_Buffer);
    exports64->addressOfNames = readDWord(pefile, diskOffset+32, DWORD_Buffer);
    exports64->addressOfOrdinals = readDWord(pefile, diskOffset+36, DWORD_Buffer);
    
    uint32_t functionsOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(exports64->addressOfFunctions), numberOfSections, sectionHeader64);
    
    for(size_t i=0;i<reverse_endianess_uint32_t(exports64->numberOfFunctions);i++)
    	exportFunctionAddresses[i] = reverse_endianess_uint32_t(readDWord(pefile, functionsOffset+i*sizeof(uint32_t), DWORD_Buffer));
    
    
    uint32_t namesOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(exports64->addressOfNames), numberOfSections, sectionHeader64);
    
    for(size_t i=0;i<reverse_endianess_uint32_t(exports64->numberOfNames);i++)
    	exportFunctionNames[i] = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(readDWord(pefile, namesOffset+i*sizeof(uint32_t), DWORD_Buffer)), numberOfSections, sectionHeader64);
    
    uint32_t ordinalsOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(exports64->addressOfOrdinals), numberOfSections, sectionHeader64);
    
    for(size_t i=0;i<reverse_endianess_uint32_t(exports64->numberOfNames);i++)
    	exportOrdinalAddresses[i] = reverse_endianess_uint16_t(readWord(pefile, ordinalsOffset+i*sizeof(uint16_t), WORD_Buffer));
    	
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);

}

void exportsConsoleOutput64(FILE* pefile, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64, struct IMAGE_EXPORT_DIRECTORY64* exports64, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses, uint16_t numberOfSections, struct SECTION_HEADER64* sectionHeader64){

	uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
	printf("EXPORT INFORMATION\n-----------------------------------\n\n");
	
	printf("Characteristics: 0x%04x\n"
        "TimeDateStamp: 0x%04x\n"
        "Major Version: 0x%02x\n"
        "Minor Version: 0x%02x\n"
        "Name: 0x%04x\n"
        "Base: 0x%04x\n"
        "Number of Functions: 0x%04x\n"
        "Number of Names: 0x%04x\n"
        "Address of Functions: 0x%04x\n"
        "Address of Names: 0x%04x\n"
        "Address of Ordinals: 0x%04x\n\n"
        ,reverse_endianess_uint32_t(exports64->characteristics), reverse_endianess_uint32_t(exports64->timeDateStamp), reverse_endianess_uint16_t(exports64->majorVersion), reverse_endianess_uint16_t(exports64->minorVersion),
        reverse_endianess_uint32_t(exports64->name), reverse_endianess_uint32_t(exports64->base), reverse_endianess_uint32_t(exports64->numberOfFunctions), reverse_endianess_uint32_t(exports64->numberOfNames),
        reverse_endianess_uint32_t(exports64->addressOfFunctions), reverse_endianess_uint32_t(exports64->addressOfNames), reverse_endianess_uint32_t(exports64->addressOfOrdinals));
    
    	printf("\t[RVA] : Exported Function\n\t-------------------------\n");
    	for(uint32_t i=0;i<reverse_endianess_uint32_t(exports64->numberOfNames);i++){
    		printf("\t[%04x] : ", exportFunctionAddresses[exportOrdinalAddresses[i]]);
    		uint32_t nameAddress = exportFunctionNames[i];
    		uint8_t letter = reverse_endianess_uint8_t(readByte(pefile, nameAddress, BYTE_Buffer));
    		while(letter != 0){
    	  		printf("%c", letter);
    	  		nameAddress++;
    	  		letter = reverse_endianess_uint8_t(readByte(pefile, nameAddress, BYTE_Buffer));
    		}
    		printf("\n");
    	}
        
        struct EXPORT_DATA_DIRECTORY64* exportDirectory = malloc(sizeof(struct EXPORT_DATA_DIRECTORY64));
        exportDirectory->virtualAddress = reverse_endianess_uint32_t(optionalHeader64->dataDirectory[0].virtualAddress);
        exportDirectory->size = reverse_endianess_uint32_t(optionalHeader64->dataDirectory[0].size);
        
        for(size_t i=0; i<reverse_endianess_uint32_t(exports64->numberOfFunctions);i++){
        
            
            if((exportDirectory->virtualAddress < exportFunctionAddresses[i]) && (exportFunctionAddresses[i] < (exportDirectory->virtualAddress + exportDirectory->size))){
                uint32_t forwardedFunctionNameRVA = convertRelativeAddressToDiskOffset64(exportFunctionAddresses[i], numberOfSections, sectionHeader64);
                uint8_t functionLetter = reverse_endianess_uint8_t(readByte(pefile, forwardedFunctionNameRVA, BYTE_Buffer));

                while(functionLetter != 0){
                    printf("%c", functionLetter);
                    forwardedFunctionNameRVA+=1;
                    functionLetter = reverse_endianess_uint8_t(readByte(pefile, forwardedFunctionNameRVA, BYTE_Buffer));
                }
                printf("\n");
            }
        }
        
        
        free(exportDirectory);
        free(BYTE_Buffer);
}

void parseImports64(FILE* pefile, size_t numID, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER64* sectionHeader64, struct IMAGE_IMPORT_DESCRIPTOR64** imports64){
    
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));

    for(size_t i=0;i<numID;i++){
    	imports64[i]->u.OriginalFirstThunk.u1.ordinal = readDWord(pefile, diskOffset, DWORD_Buffer);
    	imports64[i]->timeDateStamp = readDWord(pefile, diskOffset+4, DWORD_Buffer);
    	imports64[i]->forwarderChain = readDWord(pefile, diskOffset+8, DWORD_Buffer);
    	imports64[i]->name = readDWord(pefile, diskOffset+12, DWORD_Buffer);
    	imports64[i]->FirstThunk.u1.addressOfData = readDWord(pefile, diskOffset+16, DWORD_Buffer);
    	diskOffset += 20;
    }
    
    free(DWORD_Buffer);
}

void importsConsoleOutput64(FILE* pefile, size_t numID, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER64* sectionHeader64, struct IMAGE_IMPORT_DESCRIPTOR64** imports64){

	uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
	uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
	uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));
	
	printf("IMPORT INFORMATION\n-----------------------------------\n\n");
	
	for(size_t i=0;i<numID;i++){
		if(!((imports64[i]->u.OriginalFirstThunk.u1.ordinal == 0) && (imports64[i]->timeDateStamp == 0) && (imports64[i]->forwarderChain == 0) && (imports64[i]->name == 0) && (imports64[i]->FirstThunk.u1.addressOfData == 0))){
			printf("[IMPORT_DESCRIPTOR32]\n");
	    		printf("\timports64[%zu]->u.OriginalFirstThunk.u1.ordinal: %04x\n", i, imports64[i]->u.OriginalFirstThunk.u1.ordinal);
	    		printf("\timports64[%zu]->timeDateStamp: %04x\n", i, imports64[i]->timeDateStamp);
	    		printf("\timports64[%zu]->forwarderChain: %04x\n", i, imports64[i]->forwarderChain);
	    		printf("\timports64[%zu]->name: %04x\n", i, imports64[i]->name);
	    		printf("\timports64[%zu]->FirstThunk.u1.addressOfData: %04lx\n\n", i, imports64[i]->FirstThunk.u1.addressOfData);
	    		diskOffset += 20;
	    		
	    		uint32_t dllNameOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(imports64[i]->name), numberOfSections, sectionHeader64);
	    		uint8_t dllLetter = reverse_endianess_uint8_t(readByte(pefile, dllNameOffset, BYTE_Buffer));
		    	printf("\t[");
		    	while(dllLetter != 0 && (imports64[i]->u.OriginalFirstThunk.u1.ordinal != 0)){
		        	printf("%c", dllLetter);
		        	dllNameOffset+=1;
		        	dllLetter = reverse_endianess_uint8_t(readByte(pefile, dllNameOffset, BYTE_Buffer));
		    	}
		    	printf("]\n\n");
		    	
		    	struct IMAGE_THUNK_DATA64 tmpNames;
            
            		uint32_t tmpNamesOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(imports64[i]->u.OriginalFirstThunk.u1.ordinal), numberOfSections, sectionHeader64);
            
            		size_t namesCount=0;
            		tmpNames.u1.ordinal = reverse_endianess_uint64_t(readQWord(pefile, tmpNamesOffset, QWORD_Buffer));
            		while((tmpNames.u1.ordinal != 0)){
    				tmpNamesOffset += sizeof(uint64_t);
            			tmpNames.u1.ordinal = reverse_endianess_uint64_t(readQWord(pefile, tmpNamesOffset, QWORD_Buffer));
            			namesCount++;
            		}
            
            		struct IMAGE_THUNK_DATA64* names = malloc(namesCount * sizeof(struct IMAGE_THUNK_DATA64));
            
            		uint32_t namesOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(imports64[i]->u.OriginalFirstThunk.u1.ordinal), numberOfSections, sectionHeader64);
            
            		for(size_t j=0;j<namesCount;j++){
            			names[j].u1.ordinal = reverse_endianess_uint64_t(readQWord(pefile, namesOffset+j*sizeof(uint64_t), QWORD_Buffer));
            	
            			if(names[j].u1.ordinal != 0){
            				if(names[j].u1.ordinal <= 0x8000000000000000){
            					uint64_t functionNameOffset = convertRelativeAddressToDiskOffset64_t(names[j].u1.ordinal, numberOfSections, sectionHeader64);
            					functionNameOffset += 2; // skip the hint
            					uint8_t functionLetter = reverse_endianess_uint8_t(readByte(pefile, functionNameOffset, BYTE_Buffer));
            		
            					printf("\t\t");
            					while(functionLetter != 0){
                        				printf("%c", functionLetter);
                        				functionNameOffset++;
                        				functionLetter = reverse_endianess_uint8_t(readByte(pefile, functionNameOffset, BYTE_Buffer));
                    				}
                    				printf("\n");
            				}
            			}
            		}
            		
            		printf("\n\n");
            		
            		free(names);
            	}
    	}
    	
    	free(BYTE_Buffer);
    	free(DWORD_Buffer);
	free(QWORD_Buffer);

}

void parseException64(FILE* pefile, uint32_t diskOffset, size_t exceptionCount, struct IMAGE_EXCEPTION64* exception64){
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    
    for(size_t i=0;i<exceptionCount;i++){
    	exception64[i].startAddress = readDWord(pefile, diskOffset, DWORD_Buffer);
    	exception64[i].endAddress = readDWord(pefile, diskOffset+4, DWORD_Buffer);
    	exception64[i].unwindAddress = readDWord(pefile, diskOffset+8, DWORD_Buffer);
    	diskOffset += 12;
    }
    
    free(DWORD_Buffer);
}

void exceptionConsoleOutput64(FILE* pefile, uint32_t diskOffset, size_t exceptionCount, struct IMAGE_EXCEPTION64* exception64){

	printf("Exception Table\n-----------------------------\n");	

	for(size_t i=0;i<exceptionCount;i++){
    	    printf("exception64[%zu].startAddress: %04x\n", i, exception64[i].startAddress);
    	    printf("exception64[%zu].endAddress: %04x\n", i, exception64[i].endAddress);
    	    printf("exception64[%zu].unwindAddress: %04x\n", i, exception64[i].unwindAddress);
        }

	printf("\n");

}

void parseCertificate64(FILE* pefile, uint32_t diskOffset, size_t certificateCount, struct IMAGE_CERTIFICATE64* certificate64, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64){

    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    size_t i=0;
    
    while(diskOffset < (diskOffset + reverse_endianess_uint32_t(optionalHeader64->dataDirectory[4].size)) && (i < certificateCount)){    
            certificate64[i].dwLength = readDWord(pefile, diskOffset, DWORD_Buffer);
            certificate64[i].wRevision = readWord(pefile, diskOffset+4, WORD_Buffer);
            certificate64[i].wCertificateType = readWord(pefile, diskOffset+6, WORD_Buffer);
            diskOffset += reverse_endianess_uint32_t(certificate64[i++].dwLength);
            while(diskOffset % 8 != 0)
            	diskOffset++;
    }
    
    free(WORD_Buffer);
    free(DWORD_Buffer);

}

void certificateConsoleOutput64(FILE* pefile, size_t certificateCount, struct IMAGE_CERTIFICATE64* certificate64){
    printf("CERTIFICATE INFORMATION\n-------------------------------------------\n\n");
    for(size_t i=0;i<certificateCount;i++){
    	printf("certificate64[%zu].dwLength: %04x\n", i, reverse_endianess_uint32_t(certificate64[i].dwLength));
    	if(reverse_endianess_uint16_t(certificate64[i].wRevision) == 0x200)
    	    printf("certificate64[%zu].wRevision: WIN_CERT_REVISION_2_0\n", i);
    	else
    	    printf("certificate64[%zu].wRevision: WIN_CERT_REVISION_1_0\n", i);
    	printf("certificate64[%zu].wCertificateType: %02x\n\n", i, reverse_endianess_uint16_t(certificate64[i].wCertificateType));
    }

    printf("\n\n");
}


void parseBaseReloc64(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION64* baseReloc64){

    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));

    size_t i=0, typeCount=0;

    while(i < baseRelocCount){
        baseReloc64[i].pageRVA = reverse_endianess_uint32_t(readDWord(pefile, diskOffset, DWORD_Buffer));
        baseReloc64[i].blockSize = reverse_endianess_uint32_t(readDWord(pefile, diskOffset+4, DWORD_Buffer));
        diskOffset += 8;
        typeCount = (baseReloc64[i].blockSize - 8) / 2;  	
    	diskOffset += (typeCount * sizeof(WORD));
    	i++;
    }

    free(DWORD_Buffer);
}

void baseRelocConsoleOutput64(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION64* baseReloc64){
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    
    char* baseRelocTypes[4] = {"IMAGE_REL_BASED_ABSOLUTE", "IMAGE_REL_BASED_HIGH", "IMAGE_REL_BASED_LOW", "IMAGE_REL_BASED_HIGHLOW"};

    size_t i=0, typeCount=0;
    
    printf("BASE RELOCATIONS\n---------------------------\n\n");
    
    while(i < baseRelocCount){
    	printf("baseReloc64->pageRVA: %04x\n", baseReloc64[i].pageRVA);
    	printf("baseReloc64->blockSize: %04x\n", baseReloc64[i].blockSize);
    	typeCount = (baseReloc64[i].blockSize - 8) / 2;
    	diskOffset += (uint32_t)(2 * sizeof(DWORD));
    	printf("diskOffset: %04x\n", diskOffset + (uint32_t)(2*sizeof(DWORD)));
        printf("---------------------------\n");
        uint16_t fourbitValue = 0;
        uint16_t twelvebitValue = 0;
        //+baseReloc32[i].pageRVA
        

        while(typeCount--){
            fourbitValue = (reverse_endianess_uint16_t(readWord(pefile, diskOffset, WORD_Buffer)) >> 12);
            twelvebitValue = (reverse_endianess_uint16_t(readWord(pefile, diskOffset, WORD_Buffer)) & 0x0FFF);
            printf(
            "\t[type: 0x%02x\t(%s)]"
            "\taddress: 0x%04x\n"
            ,(fourbitValue), baseRelocTypes[fourbitValue] , (uint32_t)(twelvebitValue)+baseReloc64[i].pageRVA
            );
            diskOffset += sizeof(WORD);
        }
	printf("\n");
        baseReloc64[i].pageRVA = reverse_endianess_uint32_t(readDWord(pefile, diskOffset, DWORD_Buffer));
        baseReloc64[i++].blockSize = reverse_endianess_uint32_t(readDWord(pefile, diskOffset+4, DWORD_Buffer));
    }

    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseDebug64(FILE* pefile, size_t debugCount, uint32_t diskOffset, struct IMAGE_DEBUG_DIRECTORY64* debug64){
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    
    for(size_t i=0;i<debugCount;i++){
    	debug64[i].characteristics = readDWord(pefile, diskOffset, DWORD_Buffer);
        debug64[i].timeDateStamp = readDWord(pefile, diskOffset+4, DWORD_Buffer);
        debug64[i].majorVersion = readWord(pefile, diskOffset+8, WORD_Buffer);
        debug64[i].minorVersion = readWord(pefile, diskOffset+10, WORD_Buffer);
        debug64[i].type = readDWord(pefile, diskOffset+12, DWORD_Buffer);
        debug64[i].sizeOfData = readDWord(pefile, diskOffset+16, DWORD_Buffer);
        debug64[i].addressOfRawData = readDWord(pefile, diskOffset+20, DWORD_Buffer);
        debug64[i].pointerToRawData = readDWord(pefile, diskOffset+24, DWORD_Buffer);
        diskOffset += 28;
    }
    
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);

}

void debugConsoleOutput64(FILE* pefile, size_t debugCount, uint32_t diskOffset, struct IMAGE_DEBUG_DIRECTORY64* debug64, struct SECTION_HEADER64* sectionHeader64){
    
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    
    char* debugTypes[17] = {"IMAGE_DEBUG_TYPE_UNKNOWN", "IMAGE_DEBUG_TYPE_COFF", "IMAGE_DEBUG_TYPE_CODEVIEW", "IMAGE_DEBUG_TYPE_FPO", "IMAGE_DEBUG_TYPE_MISC", "IMAGE_DEBUG_TYPE_EXCEPTION", "IMAGE_DEBUG_TYPE_FIXUP", "IMAGE_DEBUG_TYPE_OMAP_TO_SRC", "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC", "IMAGE_DEBUG_TYPE_BORLAND", "IMAGE_DEBUG_TYPE_RESERVED10", "IMAGE_DEBUG_TYPE_CLSID", "IMAGE_DEBUG_TYPE_VC_FEATURE", "IMAGE_DEBUG_TYPE_POGO", "IMAGE_DEBUG_TYPE_ILTCG", "IMAGE_DEBUG_TYPE_MPX", "IMAGE_DEBUG_TYPE_REPRO"};
    
    
    printf("DEBUG INFORMATION\n--------------------------------\n\n");
    
    for(size_t i=0;i<debugCount;i++){
    	printf("debug64[%zu]->characteristics: %04x\n", i, reverse_endianess_uint32_t(debug64[i].characteristics));
    	printf("debug64[%zu]->timeDateStamp: %04x\n", i, reverse_endianess_uint32_t(debug64[i].timeDateStamp));
    	printf("debug64[%zu]->majorVersio: %02x\n", i, reverse_endianess_uint16_t(debug64[i].majorVersion));
    	printf("debug64[%zu]->minorVersion: %02x\n", i, reverse_endianess_uint16_t(debug64[i].minorVersion));
    	printf("debug64[%zu]->type: %04x\n", i, reverse_endianess_uint32_t(debug64[i].type));
    	printf("debug64[%zu]->sizeOfData: %04x\n", i, reverse_endianess_uint32_t(debug64[i].sizeOfData));
    	printf("debug64[%zu]->addressOfRawData: %04x\n", i, reverse_endianess_uint32_t(debug64[i].addressOfRawData));
    	printf("debug64[%zu]->pointerToRawData: %04x\n", i, reverse_endianess_uint32_t(debug64[i].pointerToRawData));
    
    
    	uint32_t cvSignatureOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(debug64[i].addressOfRawData), debugCount, sectionHeader64);
    	uint32_t cvSignature = readDWord(pefile, cvSignatureOffset, DWORD_Buffer);
    
    	
    	if(cvSignature == 0x3031424E){
    		printf("PDB Path:  ");
         	struct CV_INFO_PDB20_64 pdb20;
         	pdb20.header.Signature = readDWord(pefile, cvSignatureOffset, DWORD_Buffer);;
         	pdb20.header.Offset = readDWord(pefile, cvSignatureOffset+4, DWORD_Buffer);
         	pdb20.signature = readDWord(pefile, cvSignatureOffset+8, DWORD_Buffer);
         	pdb20.age = readDWord(pefile, cvSignatureOffset+12, DWORD_Buffer);
         	pdb20.pdbFileName = readByte(pefile, cvSignatureOffset+16, BYTE_Buffer);
         	cvSignatureOffset += 20;
         	while(pdb20.pdbFileName != 0){
           	printf("%c", pdb20.pdbFileName);
           	pdb20.pdbFileName = readByte(pefile, cvSignatureOffset++, BYTE_Buffer);
         	}
           	printf("\n");
           	
     	}
     
     	if(cvSignature == 0x52534453){
     		printf("PDB Path:  ");
         	struct CV_INFO_PDB70_64 pdb70;
         	pdb70.cvSignature = readDWord(pefile, cvSignatureOffset, DWORD_Buffer);;
         	pdb70.signature.Data1 = readDWord(pefile, cvSignatureOffset+4, DWORD_Buffer);
         	pdb70.signature.Data2 = readWord(pefile, cvSignatureOffset+8, WORD_Buffer);
         	pdb70.signature.Data3 = readWord(pefile, cvSignatureOffset+10, WORD_Buffer);
         	for(size_t j=0;j<8;j++)
             		pdb70.signature.Data4[j] = readByte(pefile, cvSignatureOffset+12+j, BYTE_Buffer);
                
         	pdb70.age = readDWord(pefile, cvSignatureOffset+20, DWORD_Buffer);
         	pdb70.pdbFileName = readByte(pefile, cvSignatureOffset+24, BYTE_Buffer);
         	cvSignatureOffset += 25; //added extra byte so as to read the next letter of the stirng.
         	while(pdb70.pdbFileName != 0){
             		printf("%c", pdb70.pdbFileName);
             		pdb70.pdbFileName = readByte(pefile, cvSignatureOffset++, BYTE_Buffer);
         	}
         	printf("\n");
           	//printf("%s\n\n", debugTypes[reverse_endianess_uint32_t(debug32[i].type)]);
     	}
     	
     	printf("%s\n\n", debugTypes[reverse_endianess_uint32_t(debug64[i].type)]);
     
     }
     
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);

}

void parseTLS64(FILE* pefile, uint32_t diskOffset, struct IMAGE_TLS_DIRECTORY64* tls64){
	uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
	uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));
	
	tls64->startAddressOfRawData = readQWord(pefile, diskOffset, QWORD_Buffer);
	tls64->endAddressOfRawData = readQWord(pefile, diskOffset+4, QWORD_Buffer);
	tls64->addressOfIndex = readQWord(pefile, diskOffset+8, QWORD_Buffer);
	tls64->addressOfCallBacks = readQWord(pefile, diskOffset+12, QWORD_Buffer);
	tls64->sizeOfZeroFill = readDWord(pefile, diskOffset+16, DWORD_Buffer);
  	tls64->characteristics = readDWord(pefile, diskOffset+20, DWORD_Buffer);

	free(DWORD_Buffer);
	free(QWORD_Buffer);
}

void tlsConsoleOutput64(FILE* pefile, uint32_t diskOffset, struct IMAGE_TLS_DIRECTORY64* tls64){

	printf("TLS Information\n---------------------------------\n");
	printf("tls64->startAddressOfRawData: %04lx\n", reverse_endianess_uint64_t(tls64->startAddressOfRawData));
	printf("tls64->endAddressOfRawData: %04lx\n", reverse_endianess_uint64_t(tls64->endAddressOfRawData));
	printf("tls64->addressOfIndex: %04lx\n", reverse_endianess_uint64_t(tls64->addressOfIndex));
	printf("tls64->addressOfCallBacks: %04lx\n", reverse_endianess_uint64_t(tls64->addressOfCallBacks));
	printf("tls64->sizeOfZeroFill: %04x\n", reverse_endianess_uint32_t(tls64->sizeOfZeroFill));
	printf("tls64->characteristics: %04x\n\n\n", reverse_endianess_uint32_t(tls64->characteristics));

}

void parseLoadConfig64(FILE* pefile, uint32_t diskOffset, struct IMAGE_LOAD_CONFIG64* loadConfig64){
	uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    	uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    	uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));
    	
    	loadConfig64->characteristics = readDWord(pefile, diskOffset, DWORD_Buffer);
    	loadConfig64->timeDateStamp = readDWord(pefile, diskOffset+4, DWORD_Buffer);
    	loadConfig64->majorVersion = readWord(pefile, diskOffset+8, WORD_Buffer);
    	loadConfig64->minorVersion = readWord(pefile, diskOffset+10, WORD_Buffer);
    	loadConfig64->globalFlagsClear = readDWord(pefile, diskOffset+12, DWORD_Buffer);
    	loadConfig64->globalFlagsSet = readDWord(pefile, diskOffset+16, DWORD_Buffer);
    	loadConfig64->criticalSectionDefaultTimeout = readDWord(pefile, diskOffset+20, DWORD_Buffer);
    	loadConfig64->deCommitFreeBlockThreshold = readQWord(pefile, diskOffset+24, QWORD_Buffer);
    	loadConfig64->deCommitTotalFreeThreshold = readQWord(pefile, diskOffset+32, QWORD_Buffer);
    	loadConfig64->lockPrefixTable = readQWord(pefile, diskOffset+40, QWORD_Buffer);
    	loadConfig64->maximumAllocationSize = readQWord(pefile, diskOffset+48, QWORD_Buffer);
    	loadConfig64->virtualMemoryThreshold = readQWord(pefile, diskOffset+56, QWORD_Buffer);
    	loadConfig64->processAffinityMask = readQWord(pefile, diskOffset+64, QWORD_Buffer);
    	loadConfig64->processHeapFlags = readDWord(pefile, diskOffset+72, DWORD_Buffer);
    	loadConfig64->cSDVersion = readWord(pefile, diskOffset+76, WORD_Buffer);
    	loadConfig64->reserved = readWord(pefile, diskOffset+78, WORD_Buffer);
    	
    	loadConfig64->editList = readQWord(pefile, diskOffset+80, QWORD_Buffer);
    	loadConfig64->securityCookie = readQWord(pefile, diskOffset+88, QWORD_Buffer);
    	loadConfig64->sEHandlerTable = readQWord(pefile, diskOffset+96, QWORD_Buffer);
    	loadConfig64->sEHandlerCount = readQWord(pefile, diskOffset+104, QWORD_Buffer);
    	loadConfig64->guardCFCheckFunctionPointer = readQWord(pefile, diskOffset+112, QWORD_Buffer);
    	loadConfig64->guardCFDispatchFunctionPointer = readQWord(pefile, diskOffset+120, QWORD_Buffer);
    	loadConfig64->guardCFFunctionTable = readQWord(pefile, diskOffset+128, QWORD_Buffer);
    	loadConfig64->guardCFFunctionCount = readQWord(pefile, diskOffset+136, QWORD_Buffer);
    	
    	loadConfig64->guardFlags = readDWord(pefile, diskOffset+144, DWORD_Buffer);
    	loadConfig64->codeIntegrity[0] = readDWord(pefile, diskOffset+148, DWORD_Buffer);
    	loadConfig64->codeIntegrity[1] = readDWord(pefile, diskOffset+152, DWORD_Buffer);
    	loadConfig64->codeIntegrity[2] = readDWord(pefile, diskOffset+156, DWORD_Buffer);
    	
    	loadConfig64->guardAddressTakenIatEntryTable = readQWord(pefile, diskOffset+160, QWORD_Buffer);
    	loadConfig64->guardAddressTakenIatEntryCount = readQWord(pefile, diskOffset+168, QWORD_Buffer);
    	loadConfig64->guardLongJumpTargetTable = readQWord(pefile, diskOffset+176, QWORD_Buffer);
    	loadConfig64->guardLongJumpTargetCount = readQWord(pefile, diskOffset+184, QWORD_Buffer);
    	
    	free(WORD_Buffer);
    	free(DWORD_Buffer);
    	free(QWORD_Buffer);
}

void loadConfigConsoleOutput64(FILE* pefile, struct IMAGE_LOAD_CONFIG64* loadConfig64){

        printf("LOAD CONFIG INFORMATION\n-----------------------------------\n\n");
	printf(
            "loadConfig64->characteristics: 0x%04x\n"
            "loadConfig64->timeDateStamp: 0x%04x\n"
            "loadConfig64->majorVersion: 0x%02x\n"
            "loadConfig64->minorVersion: 0x%02x\n"
            "loadConfig64->globalFlagsClear: 0x%04x\n"
            "loadConfig64->globalFlagsSet: 0x%04x\n"
            "loadConfig64->criticalSectionDefaultTimeout: 0x%04x\n"
            "loadConfig64->deCommitFreeBlockThreshold: 0x%04lx\n"
            "loadConfig64->deCommitTotalFreeThreshold: 0x%04lx\n"
            "loadConfig64->lockPrefixTable: 0x%04lx\n"
            "loadConfig64->maximumAllocationSize: 0x%04lx\n"
            "loadConfig64->virtualMemoryThreshold: 0x%04lx\n"
            "loadConfig64->processAffinityMask: 0x%04lx\n"
            "loadConfig64->processHeapFlags: 0x%04x\n"
            "loadConfig64->cSDVersion: 0x%02x\n"
            "loadConfig64->reserved: 0x%02x\n"
            "loadConfig64->editList: 0x%04lx\n"
            "loadConfig64->securityCookie: 0x%04lx\n"
            "loadConfig64->sEHandlerTable: 0x%04lx\n"
            "loadConfig64->sEHandlerCount: 0x%04lx\n"
            "loadConfig64->guardCFCheckFunctionPointer: 0x%04lx\n"
            "loadConfig64->guardCFDispatchFunctionPointer: 0x%04lx\n"
            "loadConfig64->guardCFFunctionTable: 0x%04lx\n"
            "loadConfig64->guardCFFunctionCount: 0x%04lx\n"
            "loadConfig64->guardFlags: 0x%04x\n"
            "loadConfig64->codeIntegrity[0]: 0x%04x\n"
            "loadConfig64->codeIntegrity[1]: 0x%04x\n"
            "loadConfig64->codeIntegrity[2]: 0x%04x\n"
            "loadConfig64->guardAddressTakenIatEntryTable: 0x%04lx\n"
            "loadConfig64->guardAddressTakenIatEntryCount: 0x%04lx\n"
            "loadConfig64->guardLongJumpTargetTable: 0x%04lx\n"
            "loadConfig64->guardLongJumpTargetCount: 0x%04lx\n"
            ,reverse_endianess_uint32_t(loadConfig64->characteristics), reverse_endianess_uint32_t(loadConfig64->timeDateStamp)
            ,reverse_endianess_uint16_t(loadConfig64->majorVersion), reverse_endianess_uint16_t(loadConfig64->minorVersion)
            ,reverse_endianess_uint32_t(loadConfig64->globalFlagsClear), reverse_endianess_uint32_t(loadConfig64->globalFlagsSet)
            ,reverse_endianess_uint32_t(loadConfig64->criticalSectionDefaultTimeout), reverse_endianess_uint64_t(loadConfig64->deCommitFreeBlockThreshold)
            ,reverse_endianess_uint64_t(loadConfig64->deCommitTotalFreeThreshold)
            ,reverse_endianess_uint64_t(loadConfig64->lockPrefixTable), reverse_endianess_uint64_t(loadConfig64->maximumAllocationSize)
            ,reverse_endianess_uint64_t(loadConfig64->virtualMemoryThreshold), reverse_endianess_uint64_t(loadConfig64->processAffinityMask)
            ,reverse_endianess_uint32_t(loadConfig64->processHeapFlags), reverse_endianess_uint16_t(loadConfig64->cSDVersion)
            ,reverse_endianess_uint16_t(loadConfig64->reserved), reverse_endianess_uint64_t(loadConfig64->editList)
            ,reverse_endianess_uint64_t(loadConfig64->securityCookie), reverse_endianess_uint64_t(loadConfig64->sEHandlerTable)
            ,reverse_endianess_uint64_t(loadConfig64->sEHandlerCount), reverse_endianess_uint64_t(loadConfig64->guardCFCheckFunctionPointer)
            ,reverse_endianess_uint64_t(loadConfig64->guardCFDispatchFunctionPointer), reverse_endianess_uint64_t(loadConfig64->guardCFFunctionTable)
            ,reverse_endianess_uint64_t(loadConfig64->guardCFFunctionCount), reverse_endianess_uint32_t(loadConfig64->guardFlags)
            ,reverse_endianess_uint32_t(loadConfig64->codeIntegrity[0]), reverse_endianess_uint32_t(loadConfig64->codeIntegrity[1])
            ,reverse_endianess_uint32_t(loadConfig64->codeIntegrity[2]), reverse_endianess_uint64_t(loadConfig64->guardAddressTakenIatEntryTable)
            ,reverse_endianess_uint64_t(loadConfig64->guardAddressTakenIatEntryCount), reverse_endianess_uint64_t(loadConfig64->guardLongJumpTargetTable)
            ,reverse_endianess_uint64_t(loadConfig64->guardLongJumpTargetCount)
        );
}

void parseBoundImport64(FILE* pefile, uint32_t diskOffset, uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR64* bounds64){
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    size_t i=0;
    
    bounds64[i].timestamp = readDWord(pefile, diskOffset, DWORD_Buffer);
    bounds64[i].offsetModuleName = readWord(pefile, diskOffset+4, WORD_Buffer);
    bounds64[i].numberOfModuleForwarderRefs = readWord(pefile, diskOffset+6, WORD_Buffer);
    boundsCount++;
    diskOffset += 8;
    	
    while((bounds64[i].timestamp != 0) && (bounds64[i].offsetModuleName != 0) && (bounds64[i].numberOfModuleForwarderRefs != 0)){
    		
    	if(bounds64[i].numberOfModuleForwarderRefs != 0){
    		struct IMAGE_BOUND_FORWARDER_REF64 tmpForwards64;
    		while((tmpForwards64.timestamp != 0) && (tmpForwards64.offsetModuleName != 0) && (tmpForwards64.reserved != 0)){
    			tmpForwards64.timestamp = readDWord(pefile, diskOffset, DWORD_Buffer);
    			tmpForwards64.offsetModuleName = readWord(pefile, diskOffset+4, WORD_Buffer);
    			tmpForwards64.reserved = readWord(pefile, diskOffset+6, WORD_Buffer);
    			diskOffset += 8;
    		}
    	}
    		
    	boundsCount++;
    	diskOffset += 8;
    		
    	bounds64[i].timestamp = readDWord(pefile, diskOffset, DWORD_Buffer);
    	bounds64[i].offsetModuleName = readWord(pefile, diskOffset+4, WORD_Buffer);
    	bounds64[i++].numberOfModuleForwarderRefs = readWord(pefile, diskOffset+6, WORD_Buffer);
    }    
    
    free(WORD_Buffer);
    free(DWORD_Buffer);


}

void boundsConsoleOutput64(FILE* pefile, uint32_t diskOffset, uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR64* bounds64){
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));

    printf("BOUND IMPORTS\n------------------\n");
    for(size_t i=0;i<boundsCount;i++){
    	printf("bounds64[%zu].timestamp: %04x\n", i, bounds64[i].timestamp);
    	printf("bounds64[%zu].offsetModuleName (RVA): %02x\n", i, bounds64[i].offsetModuleName);
    	printf("bounds64[%zu].numberOfModuleForwarderRefs: %02x\n", i, bounds64[i++].numberOfModuleForwarderRefs);
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void consoleOutput64(struct IMAGE_DOS_HEADER64* msDOSHeader64, struct IMAGE_COFF_HEADER64* coffHeader64, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64, struct SECTION_HEADER64* sectionHeader64){

    printf("\nMS-DOS Header\n-------------\n"
    "msDOSHeader64->e_magic: 0x%02x\n"
    "msDOSHeader64->e_cblp: 0x%02x\n"
    "msDOSHeader64->e_cp: 0x%02x\n"
    "msDOSHeader64->e_crlc: 0x%02x\n"
    "msDOSHeader64->e_cparhdr: 0x%02x\n"
    "msDOSHeader64->e_minalloc: 0x%02x\n"
    "msDOSHeader64->e_maxalloc: 0x%02x\n"
    "msDOSHeader64->e_ss: 0x%02x\n"
    "msDOSHeader64->e_sp: 0x%02x\n"
    "msDOSHeader64->e_csum: 0x%02x\n"
    "msDOSHeader64->e_ip: 0x%02x\n"
    "msDOSHeader64->e_cs: 0x%02x\n"
    "msDOSHeader64->e_lfarlc: 0x%02x\n"
    "msDOSHeader64->e_ovno: 0x%02x\n"
    "msDOSHeader64->e_res: 0x%02x%02x%02x%02x\n"
    "msDOSHeader64->e_oemid: 0x%02x\n"
    "msDOSHeader64->e_res2: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
    "msDOSHeader64->e_lfanew: 0x%04x\n\n"
    ,msDOSHeader64->e_magic, msDOSHeader64->e_cblp, msDOSHeader64->e_cp, msDOSHeader64->e_crlc
    ,msDOSHeader64->e_cparhdr, msDOSHeader64->e_minalloc, msDOSHeader64->e_maxalloc, msDOSHeader64->e_ss
    ,msDOSHeader64->e_sp, msDOSHeader64->e_csum, msDOSHeader64->e_ip, msDOSHeader64->e_cs
    ,msDOSHeader64->e_lfarlc, msDOSHeader64->e_ovno, msDOSHeader64->e_res[0], msDOSHeader64->e_res[1]
    ,msDOSHeader64->e_res[2], msDOSHeader64->e_res[3], msDOSHeader64->e_oemid, msDOSHeader64->e_res2[0]
    ,msDOSHeader64->e_res2[1], msDOSHeader64->e_res2[2], msDOSHeader64->e_res2[3], msDOSHeader64->e_res2[4]
    ,msDOSHeader64->e_res2[5], msDOSHeader64->e_res2[6], msDOSHeader64->e_res2[7], msDOSHeader64->e_res2[8]
    ,msDOSHeader64->e_res2[9], msDOSHeader64->e_lfanew
    );
    
    time_t coffHeaderTimestamp = reverse_endianess_uint32_t(coffHeader64->timeDateStamp);
    printf("\n\nCOFF Header\n-----------\n"
    "coffHeader64->machine: %s\n"
    "coffHeader64->numberOfSections: 0x%02x\n"
    "coffHeader64->timeDateStamp: 0x%04x\t(%s)\n"
    "coffHeader64->pointerToSymbolTable: 0x%04x\n"
    "coffHeader64->numberOfSymbols: 0x%04x\n"
    "coffHeader64->sizeOfOptionalHeader: 0x%02x\n"
    ,coffHeader64->machineArchitecture, reverse_endianess_uint16_t(coffHeader64->numberOfSections), reverse_endianess_uint32_t(coffHeader64->timeDateStamp), ctime(&coffHeaderTimestamp)
    ,reverse_endianess_uint16_t(coffHeader64->pointerToSymbolTable), reverse_endianess_uint32_t(coffHeader64->numberOfSymbols), reverse_endianess_uint16_t(coffHeader64->sizeOfOptionalHeader)
    );
    printf("coffHeader64->characteristics:\n");
    size_t k=0;
    while(strcmp(coffHeader64->characteristicsList[k], "INITIALIZATION_VALUE") != 0){
        printf("\t%s\n", coffHeader64->characteristicsList[k++]);
    }
    
    char *dataDirectoryList[16] = {"Export Table", "Import Table", "Resource Table", "Exception Table", "Certificate Table", "Base Relocation Table", "Debug", "Architecture", "Global Ptr", "TLS Table", "Load Config Table", "Bound Import", "IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"};
    printf("\n\nOptional Header\n---------------\n"
    "optionalHeader64->magic: 0x%02x\n"
    "optionalHeader64->majorLinkerVersion: 0x%x\n"
    "optionalHeader64->minorLinkerVersion: 0x%x\n"
    "optionalHeader64->sizeOfCode: 0x%04x\n"
    "optionalHeader64->sizeOfInitializedData: 0x%04x\n"
    "optionalHeader64->sizeOfUninitializedData: 0x%04x\n"
    "optionalHeader64->addressOfEntryPoint: 0x%04x\n"
    "optionalHeader64->baseOfCode: 0x%04x\n"
    "optionalHeader64->imageBase: 0x%04lx\n"
    "optionalHeader64->sectionAlignment: 0x%04x\n"
    "optionalHeader64->fileAlignment: 0x%04x\n"
    "optionalHeader64->majorOperatingSystemVersion: 0x%02x\n"
    "optionalHeader64->minorOperatingSystemVersion: 0x%02x\n"
    "optionalHeader64->majorImageVersion: 0x%02x\n"
    "optionalHeader64->minorImageVersion: 0x%02x\n"
    "optionalHeader64->majorSubsystemVersion: 0x%02x\n"
    "optionalHeader64->minorSubsystemVersion: 0x%02x\n"
    "optionalHeader64->win32VersionValue: 0x%04x\n"
    "optionalHeader64->sizeOfImage: 0x%04x\n"
    "optionalHeader64->sizeOfHeaders: 0x%04x\n"
    "optionalHeader64->checksum: 0x%04x\n"
    "optionalHeader64->subsystem: 0x%02x\n"
    "optionalHeader64->dllCharacteristics: 0x%04x\n"
    "optionalHeader64->sizeOfStackReserve: 0x%04lx\n"
    "optionalHeader64->sizeOfStackCommit: 0x%04lx\n"
    "optionalHeader64->sizeOfHeapReserve: 0x%04lx\n"
    "optionalHeader64->sizeOfHeapCommit: 0x%04lx\n"
    "optionalHeader64->loaderFlags: 0x%04x\n"
    "optionalHeader64->numberOfRvaAndSizes: 0x%04x\n"
    ,reverse_endianess_uint16_t(optionalHeader64->magic), reverse_endianess_uint8_t(optionalHeader64->majorLinkerVersion)
    ,reverse_endianess_uint8_t(optionalHeader64->minorLinkerVersion), reverse_endianess_uint32_t(optionalHeader64->sizeOfCode)
    ,reverse_endianess_uint32_t(optionalHeader64->sizeOfInitializedData), reverse_endianess_uint32_t(optionalHeader64->sizeOfUninitializedData)
    ,reverse_endianess_uint32_t(optionalHeader64->addressOfEntryPoint), reverse_endianess_uint32_t(optionalHeader64->baseOfCode)
    ,reverse_endianess_uint64_t(optionalHeader64->imageBase)
    ,reverse_endianess_uint32_t(optionalHeader64->sectionAlignment), reverse_endianess_uint32_t(optionalHeader64->fileAlignment)
    ,reverse_endianess_uint16_t(optionalHeader64->majorOperatingSystemVersion), reverse_endianess_uint16_t(optionalHeader64->minorOperatingSystemVersion)
    ,reverse_endianess_uint16_t(optionalHeader64->majorImageVersion), reverse_endianess_uint16_t(optionalHeader64->minorImageVersion)
    ,reverse_endianess_uint16_t(optionalHeader64->majorSubsystemVersion), reverse_endianess_uint16_t(optionalHeader64->minorSubsystemVersion)
    ,reverse_endianess_uint32_t(optionalHeader64->win32VersionValue), reverse_endianess_uint32_t(optionalHeader64->sizeOfImage)
    ,reverse_endianess_uint32_t(optionalHeader64->sizeOfHeaders), reverse_endianess_uint32_t(optionalHeader64->checksum)
    ,reverse_endianess_uint16_t(optionalHeader64->subsystem), reverse_endianess_uint16_t(optionalHeader64->dllCharacteristics)
    ,reverse_endianess_uint64_t(optionalHeader64->sizeOfStackReserve), reverse_endianess_uint64_t(optionalHeader64->sizeOfStackCommit)
    ,reverse_endianess_uint64_t(optionalHeader64->sizeOfHeapReserve), reverse_endianess_uint64_t(optionalHeader64->sizeOfHeapCommit)
    ,reverse_endianess_uint32_t(optionalHeader64->loaderFlags), reverse_endianess_uint32_t(optionalHeader64->numberOfRvaAndSizes)
    );
    printf("\n\tData Directories:\n\n");
    for(size_t i=0;i<16;i++){
        if((optionalHeader64->dataDirectory[i].virtualAddress != 0) && (optionalHeader64->dataDirectory[i].size != 0)){
            printf(
            "\tData Directory: %s\n"
            "\t\tVirtualAddress: 0x%02x\n"
            "\t\tSize: 0x%02x\n"

            ,dataDirectoryList[i]
            ,reverse_endianess_uint32_t(optionalHeader64->dataDirectory[i].virtualAddress)
            ,reverse_endianess_uint32_t(optionalHeader64->dataDirectory[i].size)
            );
        }
    }
    
    uint32_t numberOfRvaAndSizes = (((optionalHeader64->numberOfRvaAndSizes&255)&15)*16777216) + (((optionalHeader64->numberOfRvaAndSizes&255)>>4)*268435456) + ((((optionalHeader64->numberOfRvaAndSizes>>8)&255)&15)*65536) + ((((optionalHeader64->numberOfRvaAndSizes>>8)&255)>>4)*1048576) + (((optionalHeader64->numberOfRvaAndSizes>>16)&15)*256) + ((((optionalHeader64->numberOfRvaAndSizes>>16)&255)>>4)*4096) + (((optionalHeader64->numberOfRvaAndSizes>>24)&15)*1) + (((optionalHeader64->numberOfRvaAndSizes>>24)>>4)*16);

    printf("\n\n\n\nSection Headers\n---------------\n");
    for(size_t i=0;i<convert_WORD_To_uint16_t(coffHeader64->numberOfSections);i++){
        if(sectionHeader64[i].name != 0){
            char* sectionNameBuf = malloc(1024 * sizeof(char));
            strcpy(sectionNameBuf, "INITIALIZED_VALUE");
            char* sectionName = convert_uint64_t_ToString(sectionHeader64[i].name, sectionNameBuf);
            printf("sectionHeader64.name: 0x%04lx\t(%s)\n"
            "\tsectionHeader64.virtualSize: 0x%04x\n"
            "\tsectionHeader64.virtualAddress: 0x%04x\n"
            "\tsectionHeader64.sizeOfRawData: 0x%04x\n"
            "\tsectionHeader64.pointerToRawData: 0x%04x\n"
            "\tsectionHeader64.pointerToRelocations: 0x%04x\n"
            "\tsectionHeader64.pointerToLineNumbers: 0x%04x\n"
            "\tsectionHeader64.numberOfRelocations: 0x%02x\n"
            "\tsectionHeader64.numberOfLineNumbers: 0x%02x\n"
            "\tsectionHeader64.characteristics: 0x%04x\n\n"
            ,sectionHeader64[i].name, sectionName, sectionHeader64[i].virtualSize, sectionHeader64[i].virtualAddress, sectionHeader64[i].sizeOfRawData
            ,sectionHeader64[i].pointerToRawData, sectionHeader64[i].pointerToRelocations, sectionHeader64[i].pointerToLineNumbers
            ,sectionHeader64[i].numberOfRelocations, sectionHeader64[i].numberOfLineNumbers, sectionHeader64[i].characteristics);
            free(sectionNameBuf);
        }
    }
    
}


void parsePE64(FILE* pefile, struct switchList* psList){
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));
    
    struct IMAGE_DOS_HEADER64* msDOSHeader64 = malloc(sizeof(struct IMAGE_DOS_HEADER64));
    if(msDOSHeader64 == NULL){
    	perror("Failed to allocate memory for msDOSHeader64 structure");
    	return;
    }
    
    struct IMAGE_COFF_HEADER64* coffHeader64 = malloc(sizeof(struct IMAGE_COFF_HEADER64));
    if(coffHeader64 == NULL){
    	perror("Failed to allocate memory for coffHeader64 structure");
    	return;
    }
    
    coffHeader64->machineArchitecture = malloc(31 * sizeof(char));
    if(coffHeader64->machineArchitecture == NULL){
    	perror("Failed to allocate memory for coffHeader64->machineArchitecture structure");
    	return;
    }
    memcpy(coffHeader64->machineArchitecture, "INITIALIZATION_VALUE", 21);
    
    coffHeader64->characteristicsList = malloc(17 * sizeof(char*));
    if(coffHeader64->characteristicsList == NULL){
    	perror("Failed to allocate memory for coffHeader64->characteristicsList structure");
    	return;
    }
	
    for(size_t i=0;i<17;i++){
    	coffHeader64->characteristicsList[i] = malloc(32 * sizeof(char));
    	if(coffHeader64->characteristicsList[i] == NULL){
    		perror("Failed to allocate memory for coffHeader64->characteristicsList structure");
    		return;
    	}
    	memcpy(coffHeader64->characteristicsList[i], "INITIALIZATION_VALUE", 21);
    }
    	
    struct IMAGE_OPTIONAL_HEADER64* optionalHeader64 = malloc(sizeof(struct IMAGE_OPTIONAL_HEADER64));
    if(optionalHeader64 == NULL){
    	perror("Failed to allocate memory for optionalHeader64 structure");
    	return;
    }
    
    optionalHeader64->subsystemType = malloc(41 * sizeof(char));
    if(optionalHeader64->subsystemType == NULL){
    	perror("Failed to allocate memory for optionalHeader64->subsystemType structure");
    	return;
    }
    memcpy(optionalHeader64->subsystemType, "SUBSYSTEM_INITIALIZATION_VALUE", 31);
    
    optionalHeader64->dllCharacteristicsList = malloc(16 * sizeof(char*));
    if(optionalHeader64->dllCharacteristicsList == NULL){
    	perror("Failed to allocate memory for optionalHeader64->dllCharacteristicsList structure");
    	return;
    }
    
    for(size_t i=0;i<16;i++){
    	optionalHeader64->dllCharacteristicsList[i] = malloc(47 * sizeof(char));
    	if(optionalHeader64->dllCharacteristicsList[i] == NULL){
    		perror("Failed to allocate memory for optionalHeader64->dllCharacteristicsList structure");
    		return;
    	}
    	memcpy(optionalHeader64->dllCharacteristicsList[i], "DLL_INITIALIZATION_VALUE", 21);
    }
    

    parseMSDOSHeader64(pefile, msDOSHeader64);
    parseCoffHeader64(pefile, convert_DWORD_To_uint32_t(msDOSHeader64->e_lfanew), coffHeader64);
    parseOptionalHeader64(pefile, convert_DWORD_To_uint32_t(msDOSHeader64->e_lfanew), optionalHeader64);
    
    uint16_t numberOfSections = convert_WORD_To_uint16_t(coffHeader64->numberOfSections);
    uint32_t memoryOffset = convert_DWORD_To_uint32_t(msDOSHeader64->e_lfanew) + 24 + convert_WORD_To_uint16_t(coffHeader64->sizeOfOptionalHeader);
    struct SECTION_HEADER64* sectionHeader64 = malloc(numberOfSections * sizeof(struct SECTION_HEADER64));

    if(sectionHeader64 == NULL){
    	perror("Failed to allocate memory for sectionHeader64 structure\n");
    	return;
    }
    
    parseSectionHeaders64(pefile, numberOfSections, memoryOffset, sectionHeader64);
    
    if(!psList->exportResult){
    	consoleOutput64(msDOSHeader64, coffHeader64, optionalHeader64, sectionHeader64);
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[0].virtualAddress) != 0){
    	printf("Export Data Directory present!: %04x\n\n", reverse_endianess_uint32_t(optionalHeader64->dataDirectory[0].virtualAddress));
    	struct IMAGE_EXPORT_DIRECTORY64* exports64 = malloc(sizeof(struct IMAGE_EXPORT_DIRECTORY64));
        if(exports64 == NULL){
    	    printf("Failed to allocate memory for exports64 structure\n");
    	    return;
        }
        
        uint32_t diskOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[0].virtualAddress), numberOfSections, sectionHeader64);
        
        uint32_t* exportFunctionAddresses = calloc(reverse_endianess_uint32_t(readDWord(pefile, diskOffset+20, DWORD_Buffer)), sizeof(uint32_t));
        if(exportFunctionAddresses == NULL){
    		perror("Failed to allocate memory for exportFunctionAddresses structure\n");
    		return;
    	}
    	
        uint32_t* exportFunctionNames = calloc(reverse_endianess_uint32_t(readDWord(pefile, diskOffset+24, DWORD_Buffer)), sizeof(uint32_t));
        if(exportFunctionNames == NULL){
    		perror("Failed to allocate memory for exportFunctionNames structure\n");
    		return;
    	}
        
        uint16_t* exportOrdinalAddresses = calloc(reverse_endianess_uint32_t(readDWord(pefile, diskOffset+24, DWORD_Buffer)), sizeof(uint16_t));
        if(exportOrdinalAddresses == NULL){
    		perror("Failed to allocate memory for exportOrdinalAddresses structure\n");
    		return;
    	}
        
        parseExports64(pefile, diskOffset, numberOfSections, sectionHeader64, exports64, exportFunctionAddresses, exportFunctionNames, exportOrdinalAddresses);
        
        if(!psList->exportResult)
        	exportsConsoleOutput64(pefile, optionalHeader64, exports64, exportFunctionAddresses, exportFunctionNames, exportOrdinalAddresses, numberOfSections, sectionHeader64);
        
        free(exports64);
        free(exportFunctionAddresses);
        free(exportFunctionNames);
        free(exportOrdinalAddresses);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[1].virtualAddress) != 0){
    	struct IMAGE_IMPORT_DESCRIPTOR64** imports64 = malloc(sizeof(struct IMAGE_IMPORT_DESCRIPTOR64*));
    	if(imports64 == NULL){
    	    perror("Failed to allocate memory for imports64 structure\n");
    	    return;
    	}
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[1].virtualAddress), numberOfSections, sectionHeader64);
    	uint32_t tmpDiskOffset = diskOffset;
    	size_t numID=0;
    	
    	struct IMAGE_IMPORT_DESCRIPTOR64* tmpImports64 = malloc(sizeof(struct IMAGE_IMPORT_DESCRIPTOR64));
    	
    	tmpImports64->u.OriginalFirstThunk.u1.ordinal = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    	tmpImports64->timeDateStamp = readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer);
    	tmpImports64->forwarderChain = readDWord(pefile, tmpDiskOffset+8, DWORD_Buffer);
    	tmpImports64->name = readDWord(pefile, tmpDiskOffset+12, DWORD_Buffer);
    	tmpImports64->FirstThunk.u1.addressOfData = readDWord(pefile, tmpDiskOffset+16, DWORD_Buffer);
    	
    	while(!((tmpImports64->u.OriginalFirstThunk.u1.ordinal == 0) && (tmpImports64->timeDateStamp == 0) && (tmpImports64->forwarderChain == 0) && (tmpImports64->name == 0) && (tmpImports64->FirstThunk.u1.addressOfData == 0))){
    		tmpImports64->u.OriginalFirstThunk.u1.ordinal = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    		tmpImports64->timeDateStamp = readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer);
    		tmpImports64->forwarderChain = readDWord(pefile, tmpDiskOffset+8, DWORD_Buffer);
    		tmpImports64->name = readDWord(pefile, tmpDiskOffset+12, DWORD_Buffer);
    		tmpImports64->FirstThunk.u1.addressOfData = readDWord(pefile, tmpDiskOffset+16, DWORD_Buffer);
    		tmpDiskOffset += 20;
    		numID++;
    	}
    	
    	imports64 = realloc(imports64, (numID+1)*sizeof(struct IMAGE_IMPORT_DESCRIPTOR64*));
    	if(imports64 == NULL){
    		perror("Failed to reallocate memory for imports64\n");
    		return;
    	}
    	for(size_t i=0;i<numID;i++){
    		imports64[i] = malloc(sizeof(struct IMAGE_IMPORT_DESCRIPTOR64));
    		if(imports64[i] == NULL){
    			perror("Failed to allocate memory for IMAGE_IMPORT_DESCRIPTOR64\n");
    			return;
    		}	
    	}
    	
    	parseImports64(pefile, numID, diskOffset, numberOfSections, sectionHeader64, imports64);
    	importsConsoleOutput64(pefile, numID, diskOffset, numberOfSections, sectionHeader64, imports64);
    	
    	free(tmpImports64);
    	for(size_t i=0;i<numID;i++)
    		free(imports64[i]);
    	free(imports64);
    }
    
    if((reverse_endianess_uint16_t(optionalHeader64->magic) == 0x20b) && (reverse_endianess_uint32_t(optionalHeader64->dataDirectory[3].virtualAddress) != 0)){
    
        uint32_t diskOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[3].virtualAddress), numberOfSections, sectionHeader64);
        uint32_t tmpDiskOffset = diskOffset;
        size_t exceptionCount = 0;
    
        struct IMAGE_EXCEPTION64 tmpexception64;
        
        tmpexception64.startAddress = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
        tmpexception64.endAddress = readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer);
        tmpexception64.unwindAddress = readDWord(pefile, tmpDiskOffset+8, DWORD_Buffer);
        if((tmpexception64.startAddress != 0) && (tmpexception64.endAddress != 0) && (tmpexception64.unwindAddress != 0)){
            tmpDiskOffset += 12;
            exceptionCount++;
        }
            
        while((tmpexception64.startAddress != 0) && (tmpexception64.endAddress != 0) && (tmpexception64.unwindAddress != 0)){
            tmpexception64.startAddress = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
            tmpexception64.endAddress = readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer);
            tmpexception64.unwindAddress = readDWord(pefile, tmpDiskOffset+8, DWORD_Buffer);
            tmpDiskOffset += 12;
            exceptionCount++;
        }
    
    
    	struct IMAGE_EXCEPTION64* exception64 = malloc(exceptionCount * sizeof(struct IMAGE_EXCEPTION64));
    	if(exception64 == NULL){
    	    perror("Failed to allocate memory for exception32");
    	    return;
    	
    	}
    	
    	parseException64(pefile, diskOffset, exceptionCount, exception64);
    	exceptionConsoleOutput64(pefile, diskOffset, exceptionCount, exception64);
    	
    	free(exception64);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[4].virtualAddress) != 0){
        uint32_t diskOffset = reverse_endianess_uint32_t(optionalHeader64->dataDirectory[4].virtualAddress);
        uint32_t tmpDiskOffset = diskOffset;
        size_t certificateCount = 0;
        
        struct IMAGE_CERTIFICATE64 tmpCertificate64;
        tmpCertificate64.dwLength = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
        tmpCertificate64.wRevision = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
        tmpCertificate64.wCertificateType = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
        tmpDiskOffset += reverse_endianess_uint32_t(tmpCertificate64.dwLength);
        while(tmpDiskOffset % 8 != 0)
            tmpDiskOffset++;
        certificateCount++;

        while(tmpDiskOffset < (diskOffset + reverse_endianess_uint32_t(optionalHeader64->dataDirectory[4].size))){
            
            tmpCertificate64.dwLength = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
            tmpCertificate64.wRevision = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
            tmpCertificate64.wCertificateType = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
            tmpDiskOffset += reverse_endianess_uint32_t(tmpCertificate64.dwLength);
            while(tmpDiskOffset % 8 != 0)
            	tmpDiskOffset++;
            certificateCount++;
        }
        
        struct IMAGE_CERTIFICATE64* certificate64 = malloc(certificateCount * sizeof(struct IMAGE_CERTIFICATE64));
        parseCertificate64(pefile, diskOffset, certificateCount, certificate64, optionalHeader64);
        certificateConsoleOutput64(pefile, certificateCount, certificate64);
        free(certificate64);
    
    }
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[5].virtualAddress) != 0){
	struct IMAGE_BASE_RELOCATION64* baseReloc64 = malloc(sizeof(struct IMAGE_BASE_RELOCATION64));
	if(baseReloc64 == NULL){
		perror("Failed to allocate memory for baseReloc64");
		return;
	}
	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[5].virtualAddress), numberOfSections, sectionHeader64);
    	uint32_t tmpDiskOffset = diskOffset;
    	
    	baseReloc64->pageRVA = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset, DWORD_Buffer));
     	baseReloc64->blockSize = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer));
     	
     	tmpDiskOffset += 8;
     	size_t baseRelocCount = 0;
    	size_t typeCount = 0;
    	
    	while((baseReloc64->pageRVA != 0) && (baseReloc64->blockSize != 0)){
    		baseRelocCount++;
        	typeCount = (baseReloc64->blockSize - 8) / 2;
        	
        	tmpDiskOffset += typeCount * 2;

        	baseReloc64->pageRVA = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset, DWORD_Buffer));
        	baseReloc64->blockSize = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer));
        	tmpDiskOffset += 8;
    	}
    	
    	free(baseReloc64);
    	baseReloc64 = malloc(baseRelocCount * sizeof(struct IMAGE_BASE_RELOCATION32));

    	parseBaseReloc64(pefile, diskOffset, baseRelocCount, baseReloc64);
    	baseRelocConsoleOutput32(pefile, diskOffset, baseRelocCount, baseReloc64);
    	free(baseReloc64);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[6].virtualAddress) != 0){
    	size_t debugCount = reverse_endianess_uint32_t(optionalHeader64->dataDirectory[6].size / sizeof(struct IMAGE_DEBUG_DIRECTORY64));
    	struct IMAGE_DEBUG_DIRECTORY64* debug64 = malloc(debugCount * sizeof(struct IMAGE_DEBUG_DIRECTORY64));
    	if(debug64 == NULL){
    		perror("Failed to allocate memory for debug64");
    		return;
    	}
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[6].virtualAddress), numberOfSections, sectionHeader64);
    	
    	parseDebug64(pefile, debugCount, diskOffset, debug64);
    	debugConsoleOutput64(pefile, debugCount, diskOffset, debug64, sectionHeader64);
    	free(debug64);
    
    }
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[9].virtualAddress) != 0){
    	struct IMAGE_TLS_DIRECTORY64* tls64 = malloc(sizeof(struct IMAGE_TLS_DIRECTORY64));
    	if(tls64 == NULL){
    	    perror("Failed to allocate memory for tls64");
    	    return;
    	}
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[9].virtualAddress), numberOfSections, sectionHeader64);
    	parseTLS64(pefile, diskOffset, tls64);
    	tlsConsoleOutput64(pefile, diskOffset, tls64);
    	free(tls64);
    
    }
    
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[10].virtualAddress) != 0){
    	struct IMAGE_LOAD_CONFIG64* loadConfig64 = malloc(sizeof(struct IMAGE_LOAD_CONFIG64));
    	if(loadConfig64 == NULL){
    		perror("Failed to allocate memory for loadConfig64");
    		return;
    	}
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[10].virtualAddress), numberOfSections, sectionHeader64);
    	
    	parseLoadConfig64(pefile, diskOffset, loadConfig64);
    	loadConfigConsoleOutput64(pefile, loadConfig64);
    	free(loadConfig64);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[11].virtualAddress) != 0){
    	struct IMAGE_BOUND_IMPORT_DESCRIPTOR64 tmpBounds64;
    	uint32_t tmpDiskOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[11].virtualAddress), numberOfSections, sectionHeader64);
    	size_t boundsCount = 0;
    	
    	tmpBounds64.timestamp = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    	tmpBounds64.offsetModuleName = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
    	tmpBounds64.numberOfModuleForwarderRefs = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
    	boundsCount++;
    	tmpDiskOffset += 8;
    	
    	while((tmpBounds64.timestamp != 0) && (tmpBounds64.offsetModuleName != 0) && (tmpBounds64.numberOfModuleForwarderRefs != 0)){
    		
    		if(tmpBounds64.numberOfModuleForwarderRefs != 0){
    			struct IMAGE_BOUND_FORWARDER_REF64 tmpForwards64;
    			while((tmpForwards64.timestamp != 0) && (tmpForwards64.offsetModuleName != 0) && (tmpForwards64.reserved != 0)){
    				tmpForwards64.timestamp = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    				tmpForwards64.offsetModuleName = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
    				tmpForwards64.reserved = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
    				tmpDiskOffset += 8;
    			}
    		}
    		
    		boundsCount++;
    		tmpDiskOffset += 8;
    		
    		tmpBounds64.timestamp = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    		tmpBounds64.offsetModuleName = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
    		tmpBounds64.numberOfModuleForwarderRefs = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
    	}
    	
    	struct IMAGE_BOUND_IMPORT_DESCRIPTOR64* bounds64 = malloc(boundsCount * sizeof(struct IMAGE_BOUND_IMPORT_DESCRIPTOR64));
    	if(bounds64 == NULL){
    		perror("Failed to allocate memory for bounds64");
    		return;
    	}
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset64(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[11].virtualAddress), numberOfSections, sectionHeader64);
    	parseBoundImport64(pefile, diskOffset, boundsCount, bounds64);
    	boundsConsoleOutput64(pefile, diskOffset, boundsCount, bounds64);
    	
    	free(bounds64);
    }
    
    
    	
    for(size_t i=0;i<17;i++)
    	free(coffHeader64->characteristicsList[i]);
    	
    for(size_t i=0;i<16;i++)
    	free(optionalHeader64->dllCharacteristicsList[i]);
	
    free(msDOSHeader64);
    free(coffHeader64->machineArchitecture);
    free(coffHeader64->characteristicsList);
    free(coffHeader64);
    free(optionalHeader64->subsystemType);
    free(optionalHeader64->dllCharacteristicsList);
    free(optionalHeader64);
    free(sectionHeader64);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);

 }

}

#endif
