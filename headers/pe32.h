#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

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
    bool urlLookup;
    bool shodanLookup;
    bool dnsLookup;
    bool computeHash;
    bool capabilityDetection;
};

typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t QWORD;
typedef BYTE *LPBYTE;
typedef WORD *PDWORD;

struct GUID{
  DWORD Data1;
  WORD Data2;
  WORD Data3;
  BYTE Data4[8];
};

struct IMAGE_DOS_HEADER32{
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

struct IMAGE_COFF_HEADER32{
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

struct EXPORT_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
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


struct RESOURCE_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
};

struct IMAGE_EXCEPTION32{
    DWORD startAddress;
    DWORD endAddress;
    DWORD unwindAddress;
};

struct EXCEPTION_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
};

struct IMAGE_CERTIFICATE32{
	DWORD dwLength;
	WORD wRevision;
	WORD wCertificateType;
};

struct CERTIFICATE_DATA_DIRECTORY32{
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

struct DEBUG_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
};

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

struct ARCHITECTURE_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
};

struct GLOBAL_PTR_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
};

struct IMAGE_TLS_DIRECTORY32{
  DWORD startAddressOfRawData;
  DWORD endAddressOfRawData;
  DWORD addressOfIndex;
  DWORD addressOfCallBacks;
  DWORD sizeOfZeroFill;
  DWORD characteristics;
};


struct TLS_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
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

struct LOAD_CONFIG_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
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

struct BOUND_IMPORT_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
};

struct IAT_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
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

struct DELAY_IMPORT_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
};

struct CLR_RUNTIME_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
};

struct RESERVED_DATA_DIRECTORY32{
    DWORD virtualAddress;
    DWORD size;
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
extern uint8_t reverse_endianess_uint8_t(uint8_t value);
extern uint16_t reverse_endianess_uint16_t(uint16_t value);
extern uint32_t reverse_endianess_uint32_t(uint32_t value);
extern uint64_t reverse_endianess_uint64_t(uint64_t value);
extern uint8_t readByte(FILE* pefile, size_t offset, uint8_t* buffer);
extern uint16_t readWord(FILE* pefile, size_t offset, uint16_t* buffer);
extern uint32_t readDWord(FILE* pefile, size_t offset, uint32_t* buffer);
extern uint64_t readQWord(FILE* pefile, size_t offset, uint64_t* buffer);

extern uint16_t convert_WORD_To_uint16_t(WORD structureValue);
extern uint32_t convert_DWORD_To_uint32_t(DWORD structureValue);
extern unsigned char hexdigit2int(unsigned char xd);
extern char* convert_uint64_t_ToString(uint64_t numericalValue, char* computedString);
extern uint32_t convertRelativeAddressToDiskOffset(uint32_t relativeAddress, uint16_t numberOfSections,  struct SECTION_HEADER32* sectionHeader32);

void parseMSDOSHeader(FILE* pefile, struct IMAGE_DOS_HEADER32* msDOSHeader);
void parseCoffHeader(FILE* pefile, uint32_t elfanew, struct IMAGE_COFF_HEADER32* coffHeader);
void parseOptionalHeader32(FILE* pefile, uint32_t elfanew, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32);
void parseSectionHeaders32(FILE* pefile, uint16_t numberOfSections, uint32_t memoryOffset, struct SECTION_HEADER32* sectionHeader32);
void parseExports32(FILE* pefile, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER32* sectionHeader32, struct IMAGE_EXPORT_DIRECTORY32* exports32, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses);
void parseImports32(FILE* pefile, size_t numID, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER32* sectionHeader32, struct IMAGE_IMPORT_DESCRIPTOR32** imports32);
void parseResources32(FILE* pefile);
void parseException32(FILE* pefile, uint32_t diskOffset, size_t exceptionCount, struct IMAGE_EXCEPTION32* exception32);
void parseCertificate32(FILE* pefile, uint32_t diskOffset, size_t certificateCount, struct IMAGE_CERTIFICATE32* certificate32, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32);
void parseBaseReloc32(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION32* baseReloc32);
void parseDebug32(FILE* pefile, size_t debugCount, uint32_t diskOffset, struct IMAGE_DEBUG_DIRECTORY32* debug32);
void parseLoadConfig32(FILE* pefile, uint32_t diskOffset, struct IMAGE_LOAD_CONFIG32* loadConfig32);
void parseBoundImport32(FILE* pefile, uint32_t diskOffset, uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR32* bounds32);

void consoleOutput32(struct IMAGE_DOS_HEADER32* msDOSHeader, struct IMAGE_COFF_HEADER32* coffHeader, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32, struct SECTION_HEADER32* sectionHeader32);
void exportsConsoleOutput32(FILE* pefile, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32, struct IMAGE_EXPORT_DIRECTORY32* exports32, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses, uint16_t numberOfSections, struct SECTION_HEADER32* sectionHeader32);
void importsConsoleOutput32(FILE* pefile, size_t numID, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER32* sectionHeader32, struct IMAGE_IMPORT_DESCRIPTOR32** imports32);
void exceptionConsoleOutput32(FILE* pefile, uint32_t diskOffset, size_t exceptionCount, struct IMAGE_EXCEPTION32* exception32);
void certificateConsoleOutput32(FILE* pefile, size_t certificateCount, struct IMAGE_CERTIFICATE32* certificate32);
void baseRelocConsoleOutput32(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION32* baseReloc32);
void debugConsoleOutput32(FILE* pefile, size_t debugCount, uint32_t diskOffset, struct IMAGE_DEBUG_DIRECTORY32* debug32, struct SECTION_HEADER32* sectionHeader32);
void loadConfigConsoleOutput32(FILE* pefile, struct IMAGE_LOAD_CONFIG32* loadConfig32);
void boundsConsoleOutput32(FILE* pefile, uint32_t diskOffset, uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR32* bounds32);

uint8_t reverse_endianess_uint8_t(uint8_t value){
    uint8_t resultat = 0;
    char *source, *destination;
    uint8_t i;

    source = (char *) &value;
    destination = ((char *) &resultat) + sizeof(uint8_t);
    for (i = 0; i < sizeof(uint8_t); i++)
        *(--destination) = *(source++);

    return resultat;
}

uint16_t reverse_endianess_uint16_t(uint16_t value) {
    uint16_t resultat = 0;
    char *source, *destination;
    uint16_t i;

    source = (char *) &value;
    destination = ((char *) &resultat) + sizeof(uint16_t);
    for (i = 0; i < sizeof(uint16_t); i++)
        *(--destination) = *(source++);

    return resultat;
}

uint32_t reverse_endianess_uint32_t(uint32_t value) {
    uint32_t resultat = 0;
    char *source, *destination;
    uint32_t i;

    source = (char *) &value;
    destination = ((char *) &resultat) + sizeof(uint32_t);
    for (i = 0; i < sizeof(uint32_t); i++)
        *(--destination) = *(source++);

    return resultat;
}

uint64_t reverse_endianess_uint64_t(uint64_t value) {
    uint64_t resultat = 0;
    char *source, *destination;
    uint64_t i;

    source = (char *) &value;
    destination = ((char *) &resultat) + sizeof(uint64_t);
    for (i = 0; i < sizeof(uint64_t); i++)
        *(--destination) = *(source++);
        
    return resultat;
}

uint8_t readByte(FILE* pefile, size_t offset, uint8_t* buffer){
    size_t fReadSuccess;

    if(fseek(pefile, offset, SEEK_SET))
       perror("FATAL ERROR: Failed to seek to the specified file offset"); 
    else{
        fReadSuccess = fread(buffer, 0x01, 0x01, pefile); //buffer, size, count, stream
        if(fReadSuccess == 0x01)
            return reverse_endianess_uint8_t(*buffer);
        else
            perror("FATAL ERROR: Failed to read appropriate countOfObjects in readByte");
    }

    return 0;
}

uint16_t readWord(FILE* pefile, size_t offset, uint16_t* buffer){
    size_t fReadSuccess;

    if(fseek(pefile, offset, SEEK_SET))
       perror("FATAL ERROR: Failed to seek to the specified file offset"); 
    else{
        fReadSuccess = fread(buffer, 0x01, 0x02, pefile); //buffer, size, count, stream
        if(fReadSuccess == 0x02)
            return reverse_endianess_uint16_t(*buffer);
        else
            perror("FATAL ERROR: Failed to read appropriate countOfObjects in readWord");
    }

    return 0;
}

uint32_t readDWord(FILE* pefile, size_t offset, uint32_t* buffer){
    size_t fReadSuccess;

    if(fseek(pefile, offset, SEEK_SET))
       perror("FATAL ERROR: Failed to seek to the specified file offset"); 
    else{
        fReadSuccess = fread(buffer, 0x01, 0x04, pefile); //buffer, size, count, stream
        if(fReadSuccess == 0x04)
            return reverse_endianess_uint32_t(*buffer);
        else
            perror("FATAL ERROR: Failed to read appropriate countOfObjects in readDWord");
    }

    return 0;
}

uint64_t readQWord(FILE* pefile, size_t offset, uint64_t* buffer){
    size_t fReadSuccess;

    if(fseek(pefile, offset, SEEK_SET))
       perror("FATAL ERROR: Failed to seek to the specified file offset"); 
    else{
        fReadSuccess = fread(buffer, 0x01, 0x08, pefile); //buffer, size, count, stream
        if(fReadSuccess == 0x08)
            return reverse_endianess_uint64_t(*buffer);
        else
            perror("FATAL ERROR: Failed to read appropriate countOfObjects in readQWord");
    }

    return 0;
}

uint32_t convert_DWORD_To_uint32_t(DWORD structureValue){
    uint32_t convertedStructureValue = (((structureValue&255)&15)*16777216) + (((structureValue&255)>>4)*268435456) + ((((structureValue>>8)&255)&15)*65536) + ((((structureValue>>8)&255)>>4)*1048576) + (((structureValue>>16)&15)*256) + ((((structureValue>>16)&255)>>4)*4096) + (((structureValue>>24)&15)*1) + (((structureValue>>24)>>4)*16);
    return convertedStructureValue;
}

uint16_t convert_WORD_To_uint16_t(WORD structureValue){
    uint16_t convertedStructureValue = (structureValue&15)*256 + ((structureValue>>4)&15)*4096 + (((structureValue>>8)&15)*1) + ((structureValue>>12)&15)*16;
    return convertedStructureValue;
}

unsigned char hexdigit2int(unsigned char xd){
  if (xd <= '9')
    return xd - '0';
  xd = tolower(xd);
  if (xd == 'a')
    return 10;
  if (xd == 'b')
    return 11;
  if (xd == 'c')
    return 12;
  if (xd == 'd')
    return 13;
  if (xd == 'e')
    return 14;
  if (xd == 'f')
    return 15;
  return 0;
}

char* convert_uint64_t_ToString(uint64_t numericalValue, char* computedString){
    char* st = computedString;
    char *src = st;
    char* text = malloc(1024 * sizeof(char));
    strcpy(text, "INITIALIZED");
    char *dst = text;
    sprintf(computedString, "%04lx", numericalValue);
    while (*src != '\0')
    {
        const unsigned char high = hexdigit2int(*src++);
        const unsigned char low  = hexdigit2int(*src++);
        *dst++ = (high << 4) | low;
    }
    *dst = '\0';
    strcpy(computedString, text);
    free(text);
    return computedString;
}

uint32_t convertRelativeAddressToDiskOffset(uint32_t relativeAddress, uint16_t numberOfSections,  struct SECTION_HEADER32* sectionHeader32){
    size_t i=0;

    for(i=0; i<numberOfSections; i++){
        uint32_t sectionHeaderVirtualAddress = (((sectionHeader32[i].virtualAddress&255)&15)*16777216) + (((sectionHeader32[i].virtualAddress&255)>>4)*268435456) + ((((sectionHeader32[i].virtualAddress>>8)&255)&15)*65536) + ((((sectionHeader32[i].virtualAddress>>8)&255)>>4)*1048576) + (((sectionHeader32[i].virtualAddress>>16)&15)*256) + ((((sectionHeader32[i].virtualAddress>>16)&255)>>4)*4096) + (((sectionHeader32[i].virtualAddress>>24)&15)*1) + (((sectionHeader32[i].virtualAddress>>24)>>4)*16);
        uint32_t sectionHeaderPointerToRawData = (((sectionHeader32[i].pointerToRawData&255)&15)*16777216) + (((sectionHeader32[i].pointerToRawData&255)>>4)*268435456) + ((((sectionHeader32[i].pointerToRawData>>8)&255)&15)*65536) + ((((sectionHeader32[i].pointerToRawData>>8)&255)>>4)*1048576) + (((sectionHeader32[i].pointerToRawData>>16)&15)*256) + ((((sectionHeader32[i].pointerToRawData>>16)&255)>>4)*4096) + (((sectionHeader32[i].pointerToRawData>>24)&15)*1) + (((sectionHeader32[i].pointerToRawData>>24)>>4)*16);
        uint32_t sectionHeaderSizeOfRawData = (((sectionHeader32[i].sizeOfRawData&255)&15)*16777216) + (((sectionHeader32[i].sizeOfRawData&255)>>4)*268435456) + ((((sectionHeader32[i].sizeOfRawData>>8)&255)&15)*65536) + ((((sectionHeader32[i].sizeOfRawData>>8)&255)>>4)*1048576) + (((sectionHeader32[i].sizeOfRawData>>16)&15)*256) + ((((sectionHeader32[i].sizeOfRawData>>16)&255)>>4)*4096) + (((sectionHeader32[i].sizeOfRawData>>24)&15)*1) + (((sectionHeader32[i].sizeOfRawData>>24)>>4)*16);
        
        if((relativeAddress >= sectionHeaderVirtualAddress) && (relativeAddress <= (sectionHeaderVirtualAddress + sectionHeaderSizeOfRawData))){
            return (uint32_t)(sectionHeaderPointerToRawData + relativeAddress - sectionHeaderVirtualAddress);
        }
    }

    return 0;
}

void parseMSDOSHeader(FILE* pefile, struct IMAGE_DOS_HEADER32* msDOSHeader){
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    size_t j = 0;

    msDOSHeader->e_magic = readWord(pefile, 0x00, WORD_Buffer);
    msDOSHeader->e_cblp = readWord(pefile, 0x02, WORD_Buffer);
    msDOSHeader->e_cp = readWord(pefile, 0x04, WORD_Buffer);
    msDOSHeader->e_crlc = readWord(pefile, 0x06, WORD_Buffer);
    msDOSHeader->e_cparhdr = readWord(pefile, 0x08, WORD_Buffer);
    msDOSHeader->e_minalloc = readWord(pefile, 0x0A, WORD_Buffer);
    msDOSHeader->e_maxalloc = readWord(pefile, 0x0C, WORD_Buffer);
    msDOSHeader->e_ss = readWord(pefile, 0x0E, WORD_Buffer);
    msDOSHeader->e_sp = readWord(pefile, 0x10, WORD_Buffer);
    msDOSHeader->e_csum = readWord(pefile, 0x12, WORD_Buffer);
    msDOSHeader->e_ip = readWord(pefile, 0x14, WORD_Buffer);
    msDOSHeader->e_cs = readWord(pefile, 0x16, WORD_Buffer);
    msDOSHeader->e_lfarlc = readWord(pefile, 0x18, WORD_Buffer);
    msDOSHeader->e_ovno = readWord(pefile, 0x1A, WORD_Buffer);
    
    for(size_t i=0x1C;i<0x24;i+=0x02){
        msDOSHeader->e_res[j++] = readWord(pefile, i, WORD_Buffer);
    }

    msDOSHeader->e_oemid = readWord(pefile, 0x24, WORD_Buffer);
    
    j=0;
    for(size_t i=0x26;i<0x3C;i+=0x02){
        msDOSHeader->e_res2[j++] = readWord(pefile, i, WORD_Buffer);
    }

    msDOSHeader->e_lfanew = readDWord(pefile, 0x3C, DWORD_Buffer);

    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseCoffHeader(FILE* file, uint32_t elfanew, struct IMAGE_COFF_HEADER32* coffHeader){
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));

    coffHeader->peSignature = readDWord(file, elfanew, DWORD_Buffer);
    coffHeader->machine = readWord(file, elfanew+4, WORD_Buffer);
    coffHeader->numberOfSections = readWord(file, elfanew+6, WORD_Buffer);
    coffHeader->timeDateStamp = readDWord(file, elfanew+8, DWORD_Buffer);
    coffHeader->pointerToSymbolTable = readDWord(file, elfanew+12, DWORD_Buffer);
    coffHeader->numberOfSymbols = readDWord(file, elfanew+16, DWORD_Buffer);
    coffHeader->sizeOfOptionalHeader = readWord(file, elfanew+20, WORD_Buffer);
    coffHeader->characteristics = readWord(file, elfanew+22, WORD_Buffer);

    switch(reverse_endianess_uint16_t(coffHeader->machine)){
        case 0x0:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_UNKNOWN", 27);
            break;
        case 0x1d3:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_AM33", 24);
            break;
        case 0x8664:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_AMD64", 25);
            break;
        case 0x1c0:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_ARM", 24);
            break;
        case 0xaa64:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_ARM64", 25);
            break;
        case 0x1c4:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_ARMNT", 25);
            break;
        case 0xebc:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_EBC", 23);
            break;
        case 0x14c:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_I386", 24);
            break;
        case 0x200:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_IA64", 24);
            break;
        case 0x6232:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_LOONGARCH32", 31);
            break;
        case 0x6264:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_LOONGARCH64", 31);
            break;
        case 0x9041:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_M32R", 24);
            break;
        case 0x266:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_MIPS16", 26);
            break;
        case 0x366:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_MIPSFPU", 27);
            break;
        case 0x1f0:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_POWERPC", 27);
            break;
        case 0x1f1:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_POWERPCFP", 29);
            break;
        case 0x166:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_R4000", 25);
            break;
        case 0x5032:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_RISCV32", 27);
            break;
        case 0x5064:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_RISCV64", 27);
            break;
        case 0x5128:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_RISCV128", 28);
            break;
        case 0x1a2:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_SH3", 23);
            break;
        case 0x1a3:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_SH3DSP", 26);
            break;
        case 0x1a6:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_SH4", 23);
            break;
        case 0x1a8:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_SH5", 23);
            break;
        case 0x1c2:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_THUMB", 25);
            break;
        case 0x169:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_WCEMIPSV2", 29);
            break;
        default:
            memcpy(coffHeader->machineArchitecture, "UNDEFINED_ARCHITECTURE_ANOMALY", 31);
            break;
    }

    int imageFileCharacteristics[16] = {1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768};
    int* savedCharacteristics = calloc(16, sizeof(int));
    size_t j=0;
    uint16_t characteristics = reverse_endianess_uint16_t(coffHeader->characteristics);

    for(int i=15;i>=0;i--){
        if(((characteristics - imageFileCharacteristics[i]) >= 0) && (characteristics!=0)){
            savedCharacteristics[j++] = imageFileCharacteristics[i];
            characteristics -= imageFileCharacteristics[i];
        }
    }
    
    for(size_t i=0;i<j;i++){
        switch(savedCharacteristics[i]){
            case 1:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_RELOCS_STRIPPED", 27);
                break;
            case 2:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_EXECUTABLE_IMAGE", 28);
                break;
            case 4:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_LINE_NUMS_STRIPPED", 29);
                break;
            case 8:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_LOCAL_SYMS_STRIPPED", 31);
                break;
            case 16:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_AGGRESSIVE_WS_TRIM", 30);
                break;
            case 32:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_LARGE_ADDRESS_AWARE", 31);
                break;
            case 64:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_FUTURE_USE", 22);
                break;
            case 128:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_BYTES_REVERSED_LO", 29);
                break;
            case 256:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_32BIT_MACHINE", 25);
                break;
            case 512:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_DEBUG_STRIPPED", 26);
                break;
            case 1024:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_REMOVABLE_RUN_", 26);
                break;
            case 2048:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_NET_RUN_FROM_SWAP", 29);
                break;
            case 4096:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_SYSTEM", 18);
                break;
            case 8192:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_DLL", 15);
                break;
            case 16384:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_UP_SYSTEM_ONLY", 26);
                break;
            case 32768:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_BYTES_REVERSED_HI", 29);
                break;
            default:
                memcpy(coffHeader->characteristicsList[i], "UNKNOWN_CHARACTERISTICS_ANOMALY", 32);
                break;
        }
    }

    free(savedCharacteristics);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseOptionalHeader32(FILE* pefile, uint32_t elfanew, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32){
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));

    optionalHeader32->magic = readWord(pefile, elfanew+24, WORD_Buffer);
    optionalHeader32->majorLinkerVersion = readByte(pefile, elfanew+26, BYTE_Buffer);
    optionalHeader32->minorLinkerVersion = readByte(pefile, elfanew+27, BYTE_Buffer);
    optionalHeader32->sizeOfCode = readDWord(pefile, elfanew+28, DWORD_Buffer);
    optionalHeader32->sizeOfInitializedData = readDWord(pefile, elfanew+32, DWORD_Buffer);
    optionalHeader32->sizeOfUninitializedData = readDWord(pefile, elfanew+36, DWORD_Buffer);
    optionalHeader32->addressOfEntryPoint = readDWord(pefile, elfanew+40, DWORD_Buffer);
    optionalHeader32->baseOfCode = readDWord(pefile, elfanew+44, DWORD_Buffer);
    optionalHeader32->baseOfData = readDWord(pefile, elfanew+48, DWORD_Buffer);
    optionalHeader32->imageBase = readDWord(pefile, elfanew+52, DWORD_Buffer);
    optionalHeader32->sectionAlignment = readDWord(pefile, elfanew+56, DWORD_Buffer);
    optionalHeader32->fileAlignment = readDWord(pefile, elfanew+60, DWORD_Buffer);
    optionalHeader32->majorOperatingSystemVersion = readWord(pefile, elfanew+64, WORD_Buffer);
    optionalHeader32->minorOperatingSystemVersion = readWord(pefile, elfanew+66, WORD_Buffer);
    optionalHeader32->majorImageVersion = readWord(pefile, elfanew+68, WORD_Buffer);
    optionalHeader32->minorImageVersion = readWord(pefile, elfanew+70, WORD_Buffer);
    optionalHeader32->majorSubsystemVersion = readWord(pefile, elfanew+72, WORD_Buffer);
    optionalHeader32->minorSubsystemVersion = readWord(pefile, elfanew+74, WORD_Buffer);
    optionalHeader32->win32VersionValue = readDWord(pefile, elfanew+76, DWORD_Buffer);
    optionalHeader32->sizeOfImage = readDWord(pefile, elfanew+80, DWORD_Buffer);
    optionalHeader32->sizeOfHeaders = readDWord(pefile, elfanew+84, DWORD_Buffer);
    optionalHeader32->checksum = readDWord(pefile, elfanew+88, DWORD_Buffer);
    optionalHeader32->subsystem = readWord(pefile, elfanew+92, WORD_Buffer);
    optionalHeader32->dllCharacteristics = readWord(pefile, elfanew+94, WORD_Buffer);
    optionalHeader32->sizeOfStackReserve = readDWord(pefile, elfanew+96, DWORD_Buffer);
    optionalHeader32->sizeOfStackCommit = readDWord(pefile, elfanew+100, DWORD_Buffer);
    optionalHeader32->sizeOfHeapReserve = readDWord(pefile, elfanew+104, DWORD_Buffer);
    optionalHeader32->sizeOfHeapCommit = readDWord(pefile, elfanew+108, DWORD_Buffer);
    optionalHeader32->loaderFlags = readDWord(pefile, elfanew+112, DWORD_Buffer);
    optionalHeader32->numberOfRvaAndSizes = readDWord(pefile, elfanew+116, DWORD_Buffer);

    size_t j=0;
    size_t maxDirectories = reverse_endianess_uint32_t(optionalHeader32->numberOfRvaAndSizes);
    for(size_t i=0;i<maxDirectories;i++){
        optionalHeader32->dataDirectory[i].virtualAddress = readDWord(pefile, elfanew+120+j, DWORD_Buffer);
        j+=4;
        optionalHeader32->dataDirectory[i].size = readDWord(pefile, elfanew+120+j, DWORD_Buffer);
        j+=4;
    }

    switch(reverse_endianess_uint16_t(optionalHeader32->subsystem)){
        case 0:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_UNKNOWN", 24);
            break;
        case 1:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_NATIVE", 23);
            break;
        case 2:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_WINDOWS_GUI", 28);
            break;
        case 3:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_WINDOWS_CUI", 28);
            break;
        case 5:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_OS2_CUI", 24);
            break;
        case 7:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_POSIX_CUI", 26);
            break;
        case 8:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_NATIVE_WINDOWS", 31);
            break;
        case 9:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", 31);
            break;
        case 10:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_EFI_APPLICATION", 32);
            break;
        case 11:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", 40);
            break;
        case 12:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", 35);
            break;
        case 13:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_EFI_ROM", 24);
            break;
        case 14:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_XBOX", 21);
            break;
        case 16:
            memcpy(optionalHeader32->subsystemType, "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", 41);
            break;
        default:
            memcpy(optionalHeader32->subsystemType, "UNDEFINED_IMAGE_SUBSYSTEM_ANOMALY", 34);
            break;
    }

    int imageFileCharacteristics[16] = {1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768};
    int* savedCharacteristics = calloc(16, sizeof(int));
    j=0;
    uint16_t dllCharacteristics = reverse_endianess_uint16_t(optionalHeader32->dllCharacteristics);

    for(int i=15;i>=0;i--){
        if(((dllCharacteristics - imageFileCharacteristics[i]) >= 0) && (dllCharacteristics!=0)){
            savedCharacteristics[j++] = imageFileCharacteristics[i];
            dllCharacteristics -= imageFileCharacteristics[i];
        }
    }

    for(size_t i=0;i<j;i++){
        switch(savedCharacteristics[i]){
            case 32:
                memcpy(optionalHeader32->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", 41);
                break;
            case 64:
                memcpy(optionalHeader32->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", 38);
                break;
            case 128:
                memcpy(optionalHeader32->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", 41);
                break;
            case 256:
                memcpy(optionalHeader32->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_NX_COMPAT", 35);
                break;
            case 512:
                memcpy(optionalHeader32->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", 38);
                break;
            case 1024:
                memcpy(optionalHeader32->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_NO_SEH", 32);
                break;
            case 2048:
                memcpy(optionalHeader32->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_NO_BIND", 33);
                break;
            case 4096:
                memcpy(optionalHeader32->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_APPCONTAINER", 38);
                break;
            case 8192:
                memcpy(optionalHeader32->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", 36);
                break;
            case 16384:
                memcpy(optionalHeader32->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_GUARD_CF", 34);
                break;
            case 32768:
                memcpy(optionalHeader32->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", 47);
                break;
            default:
                memcpy(optionalHeader32->dllCharacteristicsList[i], "UNKNOWN_DLL_CHARACTERISTICS_ANOMALY", 36);
                break;
        }
    }

    free(savedCharacteristics);
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseSectionHeaders32(FILE* pefile, uint16_t numberOfSections, uint32_t memoryOffset, struct SECTION_HEADER32* sectionHeader32){

    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));

    for(size_t i=0; i<numberOfSections; i++){
        sectionHeader32[i].name = readQWord(pefile, memoryOffset+i*40, QWORD_Buffer);
        sectionHeader32[i].virtualSize = readDWord(pefile, memoryOffset+i*40+8, DWORD_Buffer);
        sectionHeader32[i].virtualAddress = readDWord(pefile, memoryOffset+i*40+12, DWORD_Buffer);
        sectionHeader32[i].sizeOfRawData = readDWord(pefile, memoryOffset+i*40+16, DWORD_Buffer);
        sectionHeader32[i].pointerToRawData = readDWord(pefile, memoryOffset+i*40+20, DWORD_Buffer);
        sectionHeader32[i].pointerToRelocations = readDWord(pefile, memoryOffset+i*40+24, DWORD_Buffer);
        sectionHeader32[i].pointerToLineNumbers = readDWord(pefile, memoryOffset+i*40+28, DWORD_Buffer);
        sectionHeader32[i].numberOfRelocations = readWord(pefile, memoryOffset+i*40+32, WORD_Buffer);
        sectionHeader32[i].numberOfLineNumbers = readWord(pefile, memoryOffset+i*40+34, WORD_Buffer);
        sectionHeader32[i].characteristics = readDWord(pefile, memoryOffset+i*40+36, DWORD_Buffer);
    }
    
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void parseExports32(FILE* pefile, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER32* sectionHeader32, struct IMAGE_EXPORT_DIRECTORY32* exports32, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses){
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));
    
    
    exports32->characteristics = readDWord(pefile, diskOffset, DWORD_Buffer);
    exports32->timeDateStamp = readDWord(pefile, diskOffset+4, DWORD_Buffer);
    exports32->majorVersion = readWord(pefile, diskOffset+8, WORD_Buffer);
    exports32->minorVersion = readWord(pefile, diskOffset+10, WORD_Buffer);
    exports32->name = readDWord(pefile, diskOffset+12, DWORD_Buffer);
    exports32->base = readDWord(pefile, diskOffset+16, DWORD_Buffer);
    exports32->numberOfFunctions = readDWord(pefile, diskOffset+20, DWORD_Buffer);
    exports32->numberOfNames = readDWord(pefile, diskOffset+24, DWORD_Buffer);
    exports32->addressOfFunctions = readDWord(pefile, diskOffset+28, DWORD_Buffer);
    exports32->addressOfNames = readDWord(pefile, diskOffset+32, DWORD_Buffer);
    exports32->addressOfOrdinals = readDWord(pefile, diskOffset+36, DWORD_Buffer);
    
    uint32_t functionsOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(exports32->addressOfFunctions), numberOfSections, sectionHeader32);
    
    for(size_t i=0;i<reverse_endianess_uint32_t(exports32->numberOfFunctions);i++)
    	exportFunctionAddresses[i] = reverse_endianess_uint32_t(readDWord(pefile, functionsOffset+i*sizeof(uint32_t), DWORD_Buffer));    
    
    uint32_t namesOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(exports32->addressOfNames), numberOfSections, sectionHeader32);
    
    for(size_t i=0;i<reverse_endianess_uint32_t(exports32->numberOfNames);i++)
    	exportFunctionNames[i] = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(readDWord(pefile, namesOffset+i*sizeof(uint32_t), DWORD_Buffer)), numberOfSections, sectionHeader32);
    
    uint32_t ordinalsOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(exports32->addressOfOrdinals), numberOfSections, sectionHeader32);
    
    for(size_t i=0;i<reverse_endianess_uint32_t(exports32->numberOfNames);i++)
    	exportOrdinalAddresses[i] = reverse_endianess_uint16_t(readWord(pefile, ordinalsOffset+i*sizeof(uint16_t), WORD_Buffer));
    	
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);

}

void exportsConsoleOutput32(FILE* pefile, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32, struct IMAGE_EXPORT_DIRECTORY32* exports32, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses, uint16_t numberOfSections, struct SECTION_HEADER32* sectionHeader32){

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
        ,reverse_endianess_uint32_t(exports32->characteristics), reverse_endianess_uint32_t(exports32->timeDateStamp), reverse_endianess_uint16_t(exports32->majorVersion), reverse_endianess_uint16_t(exports32->minorVersion),
        reverse_endianess_uint32_t(exports32->name), reverse_endianess_uint32_t(exports32->base), reverse_endianess_uint32_t(exports32->numberOfFunctions), reverse_endianess_uint32_t(exports32->numberOfNames),
        reverse_endianess_uint32_t(exports32->addressOfFunctions), reverse_endianess_uint32_t(exports32->addressOfNames), reverse_endianess_uint32_t(exports32->addressOfOrdinals));
    
    	printf("\t[RVA] : Exported Function\n\t-------------------------\n");
    	for(uint32_t i=0;i<reverse_endianess_uint32_t(exports32->numberOfNames);i++){
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
        
        struct EXPORT_DATA_DIRECTORY32* exportDirectory = malloc(sizeof(struct EXPORT_DATA_DIRECTORY32));
        exportDirectory->virtualAddress = reverse_endianess_uint32_t(optionalHeader32->dataDirectory[0].virtualAddress);
        exportDirectory->size = reverse_endianess_uint32_t(optionalHeader32->dataDirectory[0].size);
        
        for(size_t i=0; i<reverse_endianess_uint32_t(exports32->numberOfFunctions);i++){
        
            
            if((exportDirectory->virtualAddress < exportFunctionAddresses[i]) && (exportFunctionAddresses[i] < (exportDirectory->virtualAddress + exportDirectory->size))){
                uint32_t forwardedFunctionNameRVA = convertRelativeAddressToDiskOffset(exportFunctionAddresses[i], numberOfSections, sectionHeader32);
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

void parseImports32(FILE* pefile, size_t numID, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER32* sectionHeader32, struct IMAGE_IMPORT_DESCRIPTOR32** imports32){
    
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));

    for(size_t i=0;i<numID;i++){
    	imports32[i]->u.OriginalFirstThunk.u1.ordinal = readDWord(pefile, diskOffset, DWORD_Buffer);
    	imports32[i]->timeDateStamp = readDWord(pefile, diskOffset+4, DWORD_Buffer);
    	imports32[i]->forwarderChain = readDWord(pefile, diskOffset+8, DWORD_Buffer);
    	imports32[i]->name = readDWord(pefile, diskOffset+12, DWORD_Buffer);
    	imports32[i]->FirstThunk.u1.addressOfData = readDWord(pefile, diskOffset+16, DWORD_Buffer);
    	diskOffset += 20;
    }
    
    free(DWORD_Buffer);
}

void importsConsoleOutput32(FILE* pefile, size_t numID, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER32* sectionHeader32, struct IMAGE_IMPORT_DESCRIPTOR32** imports32){

	uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
	uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
	
	printf("IMPORT INFORMATION\n-----------------------------------\n\n");
	
	for(size_t i=0;i<numID;i++){
		if(!((imports32[i]->u.OriginalFirstThunk.u1.ordinal == 0) && (imports32[i]->timeDateStamp == 0) && (imports32[i]->forwarderChain == 0) && (imports32[i]->name == 0) && (imports32[i]->FirstThunk.u1.addressOfData == 0))){
			printf("[IMPORT_DESCRIPTOR32]\n");
	    		printf("\timports32[%zu]->u.OriginalFirstThunk.u1.ordinal: %04x\n", i, imports32[i]->u.OriginalFirstThunk.u1.ordinal);
	    		printf("\timports32[%zu]->timeDateStamp: %04x\n", i, imports32[i]->timeDateStamp);
	    		printf("\timports32[%zu]->forwarderChain: %04x\n", i, imports32[i]->forwarderChain);
	    		printf("\timports32[%zu]->name: %04x\n", i, imports32[i]->name);
	    		printf("\timports32[%zu]->FirstThunk.u1.addressOfData: %04x\n\n", i, imports32[i]->FirstThunk.u1.addressOfData);
	    		diskOffset += 20;
	    		
	    		uint32_t dllNameOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(imports32[i]->name), numberOfSections, sectionHeader32);
	    		uint8_t dllLetter = reverse_endianess_uint8_t(readByte(pefile, dllNameOffset, BYTE_Buffer));
		    	printf("\t[");
		    	while(dllLetter != 0 && (imports32[i]->u.OriginalFirstThunk.u1.ordinal != 0)){
		        	printf("%c", dllLetter);
		        	dllNameOffset+=1;
		        	dllLetter = reverse_endianess_uint8_t(readByte(pefile, dllNameOffset, BYTE_Buffer));
		    	}
		    	printf("]\n\n");
		    	
		    	struct IMAGE_THUNK_DATA32 tmpNames;
            
            		uint32_t tmpNamesOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(imports32[i]->u.OriginalFirstThunk.u1.ordinal), numberOfSections, sectionHeader32);
            
            		size_t namesCount=0;
            		tmpNames.u1.ordinal = reverse_endianess_uint32_t(readDWord(pefile, tmpNamesOffset, DWORD_Buffer));
            		while((tmpNames.u1.ordinal != 0)){
    				tmpNamesOffset += 4;
            			tmpNames.u1.ordinal = reverse_endianess_uint32_t(readDWord(pefile, tmpNamesOffset, DWORD_Buffer));
            			namesCount++;
            		}
            
            		struct IMAGE_THUNK_DATA32* names = malloc(namesCount * sizeof(struct IMAGE_THUNK_DATA32));
            
            		uint32_t namesOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(imports32[i]->u.OriginalFirstThunk.u1.ordinal), numberOfSections, sectionHeader32);
            
            		for(size_t j=0;j<namesCount;j++){
            			names[j].u1.ordinal = reverse_endianess_uint32_t(readDWord(pefile, namesOffset+j*sizeof(uint32_t), DWORD_Buffer));
            	
            			if(names[j].u1.ordinal != 0){
            				if(names[j].u1.ordinal <= 0x8000000){
            					uint32_t functionNameOffset = convertRelativeAddressToDiskOffset(names[j].u1.ordinal, numberOfSections, sectionHeader32);
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

}

void parseException32(FILE* pefile, uint32_t diskOffset, size_t exceptionCount, struct IMAGE_EXCEPTION32* exception32){
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    
    for(size_t i=0;i<exceptionCount;i++){
    	exception32[i].startAddress = readDWord(pefile, diskOffset, DWORD_Buffer);
    	exception32[i].endAddress = readDWord(pefile, diskOffset+4, DWORD_Buffer);
    	exception32[i].unwindAddress = readDWord(pefile, diskOffset+8, DWORD_Buffer);
    	diskOffset += 12;
    }
    
    free(DWORD_Buffer);
}

void exceptionConsoleOutput32(FILE* pefile, uint32_t diskOffset, size_t exceptionCount, struct IMAGE_EXCEPTION32* exception32){

	printf("Exception Table\n-----------------------------\n");	

	for(size_t i=0;i<exceptionCount;i++){
    	    printf("exception[%zu].startAddress: %04x\n", i, exception32[i].startAddress);
    	    printf("exception[%zu].endAddress: %04x\n", i, exception32[i].endAddress);
    	    printf("exception[%zu].unwindAddress: %04x\n", i, exception32[i].unwindAddress);
        }

	printf("\n");

}

void parseCertificate32(FILE* pefile, uint32_t diskOffset, size_t certificateCount, struct IMAGE_CERTIFICATE32* certificate32, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32){

    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    size_t i=0;
    
    while(diskOffset < (diskOffset + reverse_endianess_uint32_t(optionalHeader32->dataDirectory[4].size)) && (i < certificateCount)){    
            certificate32[i].dwLength = readDWord(pefile, diskOffset, DWORD_Buffer);
            certificate32[i].wRevision = readWord(pefile, diskOffset+4, WORD_Buffer);
            certificate32[i].wCertificateType = readWord(pefile, diskOffset+6, WORD_Buffer);
            diskOffset += reverse_endianess_uint32_t(certificate32[i++].dwLength);
            while(diskOffset % 8 != 0)
            	diskOffset++;
    }
    
    free(WORD_Buffer);
    free(DWORD_Buffer);

}

void certificateConsoleOutput32(FILE* pefile, size_t certificateCount, struct IMAGE_CERTIFICATE32* certificate32){
    printf("CERTIFICATE INFORMATION\n-------------------------------------------\n\n");
    for(size_t i=0;i<certificateCount;i++){
    	printf("certificate32[%zu].dwLength: %04x\n", i, reverse_endianess_uint32_t(certificate32[i].dwLength));
    	if(reverse_endianess_uint16_t(certificate32[i].wRevision) == 0x200)
    	    printf("certificate32[%zu].wRevision: WIN_CERT_REVISION_2_0\n", i);
    	else
    	    printf("certificate32[%zu].wRevision: WIN_CERT_REVISION_1_0\n", i);
    	printf("certificate32[%zu].wCertificateType: %02x\n\n", i, reverse_endianess_uint16_t(certificate32[i].wCertificateType));
    }

    printf("\n\n");
}


void parseBaseReloc32(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION32* baseReloc32){

    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));

    size_t i=0, typeCount=0;

    while(i < baseRelocCount){
        baseReloc32[i].pageRVA = reverse_endianess_uint32_t(readDWord(pefile, diskOffset, DWORD_Buffer));
        baseReloc32[i].blockSize = reverse_endianess_uint32_t(readDWord(pefile, diskOffset+4, DWORD_Buffer));
        diskOffset += 8;
        typeCount = (baseReloc32[i].blockSize - 8) / 2;  	
    	diskOffset += (typeCount * sizeof(WORD));
    	i++;
    }

    free(DWORD_Buffer);
}

void baseRelocConsoleOutput32(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION32* baseReloc32){
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    
    char* baseRelocTypes[4] = {"IMAGE_REL_BASED_ABSOLUTE", "IMAGE_REL_BASED_HIGH", "IMAGE_REL_BASED_LOW", "IMAGE_REL_BASED_HIGHLOW"};

    size_t i=0, typeCount=0;
    
    printf("BASE RELOCATIONS\n---------------------------\n\n");
    
    while(i < baseRelocCount){
    	printf("baseReloc32->pageRVA: %04x\n", baseReloc32[i].pageRVA);
    	printf("baseReloc32->blockSize: %04x\n", baseReloc32[i].blockSize);
    	typeCount = (baseReloc32[i].blockSize - 8) / 2;
    	diskOffset += (uint32_t)(2 * sizeof(DWORD));
    	printf("diskOffset: %04x\n", diskOffset + (uint32_t)(2*sizeof(DWORD)));
        printf("---------------------------\n");
        uint16_t fourbitValue = 0;
        uint16_t twelvebitValue = 0;        

        while(typeCount--){
            fourbitValue = (reverse_endianess_uint16_t(readWord(pefile, diskOffset, WORD_Buffer)) >> 12);
            twelvebitValue = (reverse_endianess_uint16_t(readWord(pefile, diskOffset, WORD_Buffer)) & 0x0FFF);
            printf(
            "\t[type: 0x%02x\t(%s)]"
            "\taddress: 0x%04x\n"
            ,(fourbitValue), baseRelocTypes[fourbitValue] , (uint32_t)(twelvebitValue)+baseReloc32[i].pageRVA
            );
            diskOffset += sizeof(WORD);
        }
	printf("\n");
        baseReloc32[i].pageRVA = reverse_endianess_uint32_t(readDWord(pefile, diskOffset, DWORD_Buffer));
        baseReloc32[i++].blockSize = reverse_endianess_uint32_t(readDWord(pefile, diskOffset+4, DWORD_Buffer));
    }

    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseDebug32(FILE* pefile, size_t debugCount, uint32_t diskOffset, struct IMAGE_DEBUG_DIRECTORY32* debug32){
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    
    for(size_t i=0;i<debugCount;i++){
    	debug32[i].characteristics = readDWord(pefile, diskOffset, DWORD_Buffer);
        debug32[i].timeDateStamp = readDWord(pefile, diskOffset+4, DWORD_Buffer);
        debug32[i].majorVersion = readWord(pefile, diskOffset+8, WORD_Buffer);
        debug32[i].minorVersion = readWord(pefile, diskOffset+10, WORD_Buffer);
        debug32[i].type = readDWord(pefile, diskOffset+12, DWORD_Buffer);
        debug32[i].sizeOfData = readDWord(pefile, diskOffset+16, DWORD_Buffer);
        debug32[i].addressOfRawData = readDWord(pefile, diskOffset+20, DWORD_Buffer);
        debug32[i].pointerToRawData = readDWord(pefile, diskOffset+24, DWORD_Buffer);
        diskOffset += 28;
    }
    
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);

}

void debugConsoleOutput32(FILE* pefile, size_t debugCount, uint32_t diskOffset, struct IMAGE_DEBUG_DIRECTORY32* debug32, struct SECTION_HEADER32* sectionHeader32){
    
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    
    char* debugTypes[17] = {"IMAGE_DEBUG_TYPE_UNKNOWN", "IMAGE_DEBUG_TYPE_COFF", "IMAGE_DEBUG_TYPE_CODEVIEW", "IMAGE_DEBUG_TYPE_FPO", "IMAGE_DEBUG_TYPE_MISC", "IMAGE_DEBUG_TYPE_EXCEPTION", "IMAGE_DEBUG_TYPE_FIXUP", "IMAGE_DEBUG_TYPE_OMAP_TO_SRC", "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC", "IMAGE_DEBUG_TYPE_BORLAND", "IMAGE_DEBUG_TYPE_RESERVED10", "IMAGE_DEBUG_TYPE_CLSID", "IMAGE_DEBUG_TYPE_VC_FEATURE", "IMAGE_DEBUG_TYPE_POGO", "IMAGE_DEBUG_TYPE_ILTCG", "IMAGE_DEBUG_TYPE_MPX", "IMAGE_DEBUG_TYPE_REPRO"};
    
    
    printf("DEBUG INFORMATION\n--------------------------------\n\n");
    
    for(size_t i=0;i<debugCount;i++){
    	printf("debug32[%zu]->characteristics: %04x\n", i, reverse_endianess_uint32_t(debug32[i].characteristics));
    	printf("debug32[%zu]->timeDateStamp: %04x\n", i, reverse_endianess_uint32_t(debug32[i].timeDateStamp));
    	printf("debug32[%zu]->majorVersio: %02x\n", i, reverse_endianess_uint16_t(debug32[i].majorVersion));
    	printf("debug32[%zu]->minorVersion: %02x\n", i, reverse_endianess_uint16_t(debug32[i].minorVersion));
    	printf("debug32[%zu]->type: %04x\n", i, reverse_endianess_uint32_t(debug32[i].type));
    	printf("debug32[%zu]->sizeOfData: %04x\n", i, reverse_endianess_uint32_t(debug32[i].sizeOfData));
    	printf("debug32[%zu]->addressOfRawData: %04x\n", i, reverse_endianess_uint32_t(debug32[i].addressOfRawData));
    	printf("debug32[%zu]->pointerToRawData: %04x\n", i, reverse_endianess_uint32_t(debug32[i].pointerToRawData));
    
    
    	uint32_t cvSignatureOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(debug32[i].addressOfRawData), debugCount, sectionHeader32);
    	uint32_t cvSignature = readDWord(pefile, cvSignatureOffset, DWORD_Buffer);
    
    	
    	if(cvSignature == 0x3031424E){
    		printf("PDB Path:  ");
         	struct CV_INFO_PDB20 pdb20;
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
         	struct CV_INFO_PDB70 pdb70;
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
     	}
     	
     	printf("%s\n\n", debugTypes[reverse_endianess_uint32_t(debug32[i].type)]);
     
     }
     
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);

}

void parseTLS32(FILE* pefile, uint32_t diskOffset, struct IMAGE_TLS_DIRECTORY32* tls32){
	  uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
	
	  tls32->startAddressOfRawData = readDWord(pefile, diskOffset, DWORD_Buffer);
	  tls32->endAddressOfRawData = readDWord(pefile, diskOffset+4, DWORD_Buffer);
	  tls32->addressOfIndex = readDWord(pefile, diskOffset+8, DWORD_Buffer);
	  tls32->addressOfCallBacks = readDWord(pefile, diskOffset+12, DWORD_Buffer);
	  tls32->sizeOfZeroFill = readDWord(pefile, diskOffset+16, DWORD_Buffer);
    tls32->characteristics = readDWord(pefile, diskOffset+20, DWORD_Buffer);

	  free(DWORD_Buffer);
}

void tlsConsoleOutput32(FILE* pefile, uint32_t diskOffset, struct IMAGE_TLS_DIRECTORY32* tls32){

	    printf("TLS Information\n---------------------------------\n");
	    printf("tls32->startAddressOfRawData: %04x\n", tls32->startAddressOfRawData);
	    printf("tls32->endAddressOfRawData: %04x\n", tls32->endAddressOfRawData);
	    printf("tls32->addressOfIndex: %04x\n", tls32->addressOfIndex);
	    printf("tls32->addressOfCallBacks: %04x\n", tls32->addressOfCallBacks);
	    printf("tls32->sizeOfZeroFill: %04x\n", tls32->sizeOfZeroFill);
	    printf("tls32->characteristics: %04x\n\n\n", tls32->characteristics);

}

void parseLoadConfig32(FILE* pefile, uint32_t diskOffset, struct IMAGE_LOAD_CONFIG32* loadConfig32){
	    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    	uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    	
    	loadConfig32->characteristics = readDWord(pefile, diskOffset, DWORD_Buffer);
    	loadConfig32->timeDateStamp = readDWord(pefile, diskOffset+4, DWORD_Buffer);
    	loadConfig32->majorVersion = readWord(pefile, diskOffset+8, WORD_Buffer);
    	loadConfig32->minorVersion = readWord(pefile, diskOffset+10, WORD_Buffer);
    	loadConfig32->globalFlagsClear = readDWord(pefile, diskOffset+12, DWORD_Buffer);
    	loadConfig32->globalFlagsSet = readDWord(pefile, diskOffset+16, DWORD_Buffer);
    	loadConfig32->criticalSectionDefaultTimeout = readDWord(pefile, diskOffset+20, DWORD_Buffer);
    	loadConfig32->deCommitFreeBlockThreshold = readDWord(pefile, diskOffset+24, DWORD_Buffer);
    	loadConfig32->deCommitTotalFreeThreshold = readDWord(pefile, diskOffset+28, DWORD_Buffer);
    	loadConfig32->lockPrefixTable = readDWord(pefile, diskOffset+32, DWORD_Buffer);
    	loadConfig32->maximumAllocationSize = readDWord(pefile, diskOffset+36, DWORD_Buffer);
    	loadConfig32->virtualMemoryThreshold = readDWord(pefile, diskOffset+40, DWORD_Buffer);
    	loadConfig32->processAffinityMask = readDWord(pefile, diskOffset+44, DWORD_Buffer);
    	loadConfig32->processHeapFlags = readDWord(pefile, diskOffset+48, DWORD_Buffer);
    	loadConfig32->cSDVersion = readWord(pefile, diskOffset+52, WORD_Buffer);
    	loadConfig32->reserved = readWord(pefile, diskOffset+54, WORD_Buffer);
    	loadConfig32->editList = readDWord(pefile, diskOffset+56, DWORD_Buffer);
    	loadConfig32->securityCookie = readDWord(pefile, diskOffset+60, DWORD_Buffer);
    	loadConfig32->sEHandlerTable = readDWord(pefile, diskOffset+64, DWORD_Buffer);
    	loadConfig32->sEHandlerCount = readDWord(pefile, diskOffset+68, DWORD_Buffer);
    	loadConfig32->guardCFCheckFunctionPointer = readDWord(pefile, diskOffset+72, DWORD_Buffer);
    	loadConfig32->guardCFDispatchFunctionPointer = readDWord(pefile, diskOffset+76, DWORD_Buffer);
    	loadConfig32->guardCFFunctionTable = readDWord(pefile, diskOffset+80, DWORD_Buffer);
    	loadConfig32->guardCFFunctionCount = readDWord(pefile, diskOffset+84, DWORD_Buffer);
    	loadConfig32->guardFlags = readDWord(pefile, diskOffset+88, DWORD_Buffer);
    	loadConfig32->codeIntegrity[0] = readDWord(pefile, diskOffset+92, DWORD_Buffer);
    	loadConfig32->codeIntegrity[1] = readDWord(pefile, diskOffset+96, DWORD_Buffer);
    	loadConfig32->codeIntegrity[2] = readDWord(pefile, diskOffset+100, DWORD_Buffer);
    	loadConfig32->guardAddressTakenIatEntryTable = readDWord(pefile, diskOffset+104, DWORD_Buffer);
    	loadConfig32->guardAddressTakenIatEntryCount = readDWord(pefile, diskOffset+108, DWORD_Buffer);
    	loadConfig32->guardLongJumpTargetTable = readDWord(pefile, diskOffset+112, DWORD_Buffer);
    	loadConfig32->guardLongJumpTargetCount = readDWord(pefile, diskOffset+116, DWORD_Buffer);
    	
    	free(WORD_Buffer);
    	free(DWORD_Buffer);
}

void loadConfigConsoleOutput32(FILE* pefile, struct IMAGE_LOAD_CONFIG32* loadConfig32){

        printf("LOAD CONFIG INFORMATION\n-----------------------------------\n\n");
	printf(
            "loadConfig32->characteristics: 0x%04x\n"
            "loadConfig32->timeDateStamp: 0x%04x\n"
            "loadConfig32->majorVersion: 0x%02x\n"
            "loadConfig32->minorVersion: 0x%02x\n"
            "loadConfig32->globalFlagsClear: 0x%04x\n"
            "loadConfig32->globalFlagsSet: 0x%04x\n"
            "loadConfig32->criticalSectionDefaultTimeout: 0x%04x\n"
            "loadConfig32->deCommitFreeBlockThreshold: 0x%04x\n"
            "loadConfig32->deCommitTotalFreeThreshold: 0x%04x\n"
            "loadConfig32->lockPrefixTable: 0x%04x\n"
            "loadConfig32->maximumAllocationSize: 0x%04x\n"
            "loadConfig32->virtualMemoryThreshold: 0x%04x\n"
            "loadConfig32->processAffinityMask: 0x%04x\n"
            "loadConfig32->processHeapFlags: 0x%04x\n"
            "loadConfig32->cSDVersion: 0x%02x\n"
            "loadConfig32->reserved: 0x%02x\n"
            "loadConfig32->editList: 0x%04x\n"
            "loadConfig32->securityCookie: 0x%04x\n"
            "loadConfig32->sEHandlerTable: 0x%04x\n"
            "loadConfig32->sEHandlerCount: 0x%04x\n"
            "loadConfig32->guardCFCheckFunctionPointer: 0x%04x\n"
            "loadConfig32->guardCFDispatchFunctionPointer: 0x%04x\n"
            "loadConfig32->guardCFFunctionTable: 0x%04x\n"
            "loadConfig32->guardCFFunctionCount: 0x%04x\n"
            "loadConfig32->guardFlags: 0x%04x\n"
            "loadConfig32->codeIntegrity[0]: 0x%04x\n"
            "loadConfig32->codeIntegrity[1]: 0x%04x\n"
            "loadConfig32->codeIntegrity[2]: 0x%04x\n"
            "loadConfig32->guardAddressTakenIatEntryTable: 0x%04x\n"
            "loadConfig32->guardAddressTakenIatEntryCount: 0x%04x\n"
            "loadConfig32->guardLongJumpTargetTable: 0x%04x\n"
            "loadConfig32->guardLongJumpTargetCount: 0x%04x\n"
            ,reverse_endianess_uint32_t(loadConfig32->characteristics), reverse_endianess_uint32_t(loadConfig32->timeDateStamp)
            ,reverse_endianess_uint16_t(loadConfig32->majorVersion), reverse_endianess_uint16_t(loadConfig32->minorVersion)
            ,reverse_endianess_uint32_t(loadConfig32->globalFlagsClear), reverse_endianess_uint32_t(loadConfig32->globalFlagsSet)
            ,reverse_endianess_uint32_t(loadConfig32->criticalSectionDefaultTimeout), reverse_endianess_uint32_t(loadConfig32->deCommitFreeBlockThreshold)
            ,reverse_endianess_uint32_t(loadConfig32->deCommitTotalFreeThreshold)
            ,reverse_endianess_uint32_t(loadConfig32->lockPrefixTable), reverse_endianess_uint32_t(loadConfig32->maximumAllocationSize)
            ,reverse_endianess_uint32_t(loadConfig32->virtualMemoryThreshold), reverse_endianess_uint32_t(loadConfig32->processAffinityMask)
            ,reverse_endianess_uint32_t(loadConfig32->processHeapFlags), reverse_endianess_uint16_t(loadConfig32->cSDVersion)
            ,reverse_endianess_uint16_t(loadConfig32->reserved), reverse_endianess_uint32_t(loadConfig32->editList)
            ,reverse_endianess_uint32_t(loadConfig32->securityCookie), reverse_endianess_uint32_t(loadConfig32->sEHandlerTable)
            ,reverse_endianess_uint32_t(loadConfig32->sEHandlerCount), reverse_endianess_uint32_t(loadConfig32->guardCFCheckFunctionPointer)
            ,reverse_endianess_uint32_t(loadConfig32->guardCFDispatchFunctionPointer), reverse_endianess_uint32_t(loadConfig32->guardCFFunctionTable)
            ,reverse_endianess_uint32_t(loadConfig32->guardCFFunctionCount), reverse_endianess_uint32_t(loadConfig32->guardFlags)
            ,reverse_endianess_uint32_t(loadConfig32->codeIntegrity[0]), reverse_endianess_uint32_t(loadConfig32->codeIntegrity[1])
            ,reverse_endianess_uint32_t(loadConfig32->codeIntegrity[2]), reverse_endianess_uint32_t(loadConfig32->guardAddressTakenIatEntryTable)
            ,reverse_endianess_uint32_t(loadConfig32->guardAddressTakenIatEntryCount), reverse_endianess_uint32_t(loadConfig32->guardLongJumpTargetTable)
            ,reverse_endianess_uint32_t(loadConfig32->guardLongJumpTargetCount)
        );
}

void parseBoundImport32(FILE* pefile, uint32_t diskOffset, uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR32* bounds32){
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    size_t i=0;
    
    bounds32[i].timestamp = readDWord(pefile, diskOffset, DWORD_Buffer);
    bounds32[i].offsetModuleName = readWord(pefile, diskOffset+4, WORD_Buffer);
    bounds32[i].numberOfModuleForwarderRefs = readWord(pefile, diskOffset+6, WORD_Buffer);
    boundsCount++;
    diskOffset += 8;
    	
    while((bounds32[i].timestamp != 0) && (bounds32[i].offsetModuleName != 0) && (bounds32[i].numberOfModuleForwarderRefs != 0)){
    		
    	if(bounds32[i].numberOfModuleForwarderRefs != 0){
    		struct IMAGE_BOUND_FORWARDER_REF32 tmpForwards32;
    		while((tmpForwards32.timestamp != 0) && (tmpForwards32.offsetModuleName != 0) && (tmpForwards32.reserved != 0)){
    			tmpForwards32.timestamp = readDWord(pefile, diskOffset, DWORD_Buffer);
    			tmpForwards32.offsetModuleName = readWord(pefile, diskOffset+4, WORD_Buffer);
    			tmpForwards32.reserved = readWord(pefile, diskOffset+6, WORD_Buffer);
    			diskOffset += 8;
    		}
    	}
    		
    	boundsCount++;
    	diskOffset += 8;
    		
    	bounds32[i].timestamp = readDWord(pefile, diskOffset, DWORD_Buffer);
    	bounds32[i].offsetModuleName = readWord(pefile, diskOffset+4, WORD_Buffer);
    	bounds32[i++].numberOfModuleForwarderRefs = readWord(pefile, diskOffset+6, WORD_Buffer);
    }    
    
    free(WORD_Buffer);
    free(DWORD_Buffer);

}

void boundsConsoleOutput32(FILE* pefile, uint32_t diskOffset, uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR32* bounds32){
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));

    printf("BOUND IMPORTS\n------------------\n");
    for(size_t i=0;i<boundsCount;i++){
    	printf("bounds32[%zu].timestamp: %04x\n", i, bounds32[i].timestamp);
    	printf("bounds32[%zu].offsetModuleName (RVA): %02x\n", i, bounds32[i].offsetModuleName);
    	printf("bounds32[%zu].numberOfModuleForwarderRefs: %02x\n", i, bounds32[i++].numberOfModuleForwarderRefs);
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}


void consoleOutput32(struct IMAGE_DOS_HEADER32* msDOSHeader, struct IMAGE_COFF_HEADER32* coffHeader, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32, struct SECTION_HEADER32* sectionHeader32){

    printf("\nMS-DOS Header\n-------------\n"
    "msDOSHeader->e_magic: 0x%02x\n"
    "msDOSHeader->e_cblp: 0x%02x\n"
    "msDOSHeader->e_cp: 0x%02x\n"
    "msDOSHeader->e_crlc: 0x%02x\n"
    "msDOSHeader->e_cparhdr: 0x%02x\n"
    "msDOSHeader->e_minalloc: 0x%02x\n"
    "msDOSHeader->e_maxalloc: 0x%02x\n"
    "msDOSHeader->e_ss: 0x%02x\n"
    "msDOSHeader->e_sp: 0x%02x\n"
    "msDOSHeader->e_csum: 0x%02x\n"
    "msDOSHeader->e_ip: 0x%02x\n"
    "msDOSHeader->e_cs: 0x%02x\n"
    "msDOSHeader->e_lfarlc: 0x%02x\n"
    "msDOSHeader->e_ovno: 0x%02x\n"
    "msDOSHeader->e_res: 0x%02x%02x%02x%02x\n"
    "msDOSHeader->e_oemid: 0x%02x\n"
    "msDOSHeader->e_res2: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
    "msDOSHeader->e_lfanew: 0x%04x\n\n"
    ,msDOSHeader->e_magic, msDOSHeader->e_cblp, msDOSHeader->e_cp, msDOSHeader->e_crlc
    ,msDOSHeader->e_cparhdr, msDOSHeader->e_minalloc, msDOSHeader->e_maxalloc, msDOSHeader->e_ss
    ,msDOSHeader->e_sp, msDOSHeader->e_csum, msDOSHeader->e_ip, msDOSHeader->e_cs
    ,msDOSHeader->e_lfarlc, msDOSHeader->e_ovno, msDOSHeader->e_res[0], msDOSHeader->e_res[1]
    ,msDOSHeader->e_res[2], msDOSHeader->e_res[3], msDOSHeader->e_oemid, msDOSHeader->e_res2[0]
    ,msDOSHeader->e_res2[1], msDOSHeader->e_res2[2], msDOSHeader->e_res2[3], msDOSHeader->e_res2[4]
    ,msDOSHeader->e_res2[5], msDOSHeader->e_res2[6], msDOSHeader->e_res2[7], msDOSHeader->e_res2[8]
    ,msDOSHeader->e_res2[9], msDOSHeader->e_lfanew
    );
    
    time_t coffHeaderTimestamp = reverse_endianess_uint32_t(coffHeader->timeDateStamp);
    printf("\n\nCOFF Header\n-----------\n"
    "coffHeader->machine: %s\n"
    "coffHeader->numberOfSections: 0x%02x\n"
    "coffHeader->timeDateStamp: 0x%04x\t(%s)\n"
    "coffHeader->pointerToSymbolTable: 0x%04x\n"
    "coffHeader->numberOfSymbols: 0x%04x\n"
    "coffHeader->sizeOfOptionalHeader: 0x%02x\n"
    ,coffHeader->machineArchitecture, reverse_endianess_uint16_t(coffHeader->numberOfSections), reverse_endianess_uint32_t(coffHeader->timeDateStamp), ctime(&coffHeaderTimestamp)
    ,reverse_endianess_uint16_t(coffHeader->pointerToSymbolTable), reverse_endianess_uint32_t(coffHeader->numberOfSymbols), reverse_endianess_uint16_t(coffHeader->sizeOfOptionalHeader)
    );
    printf("coffHeader->characteristics:\n");
    size_t k=0;
    while(strcmp(coffHeader->characteristicsList[k], "INITIALIZATION_VALUE") != 0){
        printf("\t%s\n", coffHeader->characteristicsList[k++]);
    }
    
    char *dataDirectoryList[16] = {"Export Table", "Import Table", "Resource Table", "Exception Table", "Certificate Table", "Base Relocation Table", "Debug", "Architecture", "Global Ptr", "TLS Table", "Load Config Table", "Bound Import", "IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"};
    printf("\n\nOptional Header\n---------------\n"
    "optionalHeader32->magic: 0x%02x\n"
    "optionalHeader32->majorLinkerVersion: 0x%x\n"
    "optionalHeader32->minorLinkerVersion: 0x%x\n"
    "optionalHeader32->sizeOfCode: 0x%04x\n"
    "optionalHeader32->sizeOfInitializedData: 0x%04x\n"
    "optionalHeader32->sizeOfUninitializedData: 0x%04x\n"
    "optionalHeader32->addressOfEntryPoint: 0x%04x\n"
    "optionalHeader32->baseOfCode: 0x%04x\n"
    "optionalHeader32->baseOfData: 0x%04x\n"
    "optionalHeader32->imageBase: 0x%04x\n"
    "optionalHeader32->sectionAlignment: 0x%04x\n"
    "optionalHeader32->fileAlignment: 0x%04x\n"
    "optionalHeader32->majorOperatingSystemVersion: 0x%02x\n"
    "optionalHeader32->minorOperatingSystemVersion: 0x%02x\n"
    "optionalHeader32->majorImageVersion: 0x%02x\n"
    "optionalHeader32->minorImageVersion: 0x%02x\n"
    "optionalHeader32->majorSubsystemVersion: 0x%02x\n"
    "optionalHeader32->minorSubsystemVersion: 0x%02x\n"
    "optionalHeader32->win32VersionValue: 0x%04x\n"
    "optionalHeader32->sizeOfImage: 0x%04x\n"
    "optionalHeader32->sizeOfHeaders: 0x%04x\n"
    "optionalHeader32->checksum: 0x%04x\n"
    "optionalHeader32->subsystem: 0x%02x\n"
    "optionalHeader32->dllCharacteristics: 0x%04x\n"
    "optionalHeader32->sizeOfStackReserve: 0x%04x\n"
    "optionalHeader32->sizeOfStackCommit: 0x%04x\n"
    "optionalHeader32->sizeOfHeapReserve: 0x%04x\n"
    "optionalHeader32->sizeOfHeapCommit: 0x%04x\n"
    "optionalHeader32->loaderFlags: 0x%04x\n"
    "optionalHeader32->numberOfRvaAndSizes: 0x%04x\n"
    ,reverse_endianess_uint16_t(optionalHeader32->magic), reverse_endianess_uint8_t(optionalHeader32->majorLinkerVersion)
    ,reverse_endianess_uint8_t(optionalHeader32->minorLinkerVersion), reverse_endianess_uint32_t(optionalHeader32->sizeOfCode)
    ,reverse_endianess_uint32_t(optionalHeader32->sizeOfInitializedData), reverse_endianess_uint32_t(optionalHeader32->sizeOfUninitializedData)
    ,reverse_endianess_uint32_t(optionalHeader32->addressOfEntryPoint), reverse_endianess_uint32_t(optionalHeader32->baseOfCode)
    ,reverse_endianess_uint32_t(optionalHeader32->baseOfData), reverse_endianess_uint32_t(optionalHeader32->imageBase)
    ,reverse_endianess_uint32_t(optionalHeader32->sectionAlignment), reverse_endianess_uint32_t(optionalHeader32->fileAlignment)
    ,reverse_endianess_uint16_t(optionalHeader32->majorOperatingSystemVersion), reverse_endianess_uint16_t(optionalHeader32->minorOperatingSystemVersion)
    ,reverse_endianess_uint16_t(optionalHeader32->majorImageVersion), reverse_endianess_uint16_t(optionalHeader32->minorImageVersion)
    ,reverse_endianess_uint16_t(optionalHeader32->majorSubsystemVersion), reverse_endianess_uint16_t(optionalHeader32->minorSubsystemVersion)
    ,reverse_endianess_uint32_t(optionalHeader32->win32VersionValue), reverse_endianess_uint32_t(optionalHeader32->sizeOfImage)
    ,reverse_endianess_uint32_t(optionalHeader32->sizeOfHeaders), reverse_endianess_uint32_t(optionalHeader32->checksum)
    ,reverse_endianess_uint16_t(optionalHeader32->subsystem), reverse_endianess_uint16_t(optionalHeader32->dllCharacteristics)
    ,reverse_endianess_uint32_t(optionalHeader32->sizeOfStackReserve), reverse_endianess_uint32_t(optionalHeader32->sizeOfStackCommit)
    ,reverse_endianess_uint32_t(optionalHeader32->sizeOfHeapReserve), reverse_endianess_uint32_t(optionalHeader32->sizeOfHeapCommit)
    ,reverse_endianess_uint32_t(optionalHeader32->loaderFlags), reverse_endianess_uint32_t(optionalHeader32->numberOfRvaAndSizes)
    );
    printf("\n\tData Directories:\n\n");
    for(size_t i=0;i<16;i++){
        if((optionalHeader32->dataDirectory[i].virtualAddress != 0) && (optionalHeader32->dataDirectory[i].size != 0)){
            printf(
            "\tData Directory: %s\n"
            "\t\tVirtualAddress: 0x%02x\n"
            "\t\tSize: 0x%02x\n"

            ,dataDirectoryList[i]
            ,reverse_endianess_uint32_t(optionalHeader32->dataDirectory[i].virtualAddress)
            ,reverse_endianess_uint32_t(optionalHeader32->dataDirectory[i].size)
            );
        }
    }
    
    uint32_t numberOfRvaAndSizes = (((optionalHeader32->numberOfRvaAndSizes&255)&15)*16777216) + (((optionalHeader32->numberOfRvaAndSizes&255)>>4)*268435456) + ((((optionalHeader32->numberOfRvaAndSizes>>8)&255)&15)*65536) + ((((optionalHeader32->numberOfRvaAndSizes>>8)&255)>>4)*1048576) + (((optionalHeader32->numberOfRvaAndSizes>>16)&15)*256) + ((((optionalHeader32->numberOfRvaAndSizes>>16)&255)>>4)*4096) + (((optionalHeader32->numberOfRvaAndSizes>>24)&15)*1) + (((optionalHeader32->numberOfRvaAndSizes>>24)>>4)*16);

    printf("\n\n\n\nSection Headers\n---------------\n");
    for(size_t i=0;i<convert_WORD_To_uint16_t(coffHeader->numberOfSections);i++){
        if(sectionHeader32[i].name != 0){
            char* sectionNameBuf = malloc(1024 * sizeof(char));
            strcpy(sectionNameBuf, "INITIALIZED_VALUE");
            char* sectionName = convert_uint64_t_ToString(sectionHeader32[i].name, sectionNameBuf);
            printf("sectionHeader.name: 0x%04lx\t(%s)\n"
            "\tsectionHeader.virtualSize: 0x%04x\n"
            "\tsectionHeader.virtualAddress: 0x%04x\n"
            "\tsectionHeader.sizeOfRawData: 0x%04x\n"
            "\tsectionHeader.pointerToRawData: 0x%04x\n"
            "\tsectionHeader.pointerToRelocations: 0x%04x\n"
            "\tsectionHeader.pointerToLineNumbers: 0x%04x\n"
            "\tsectionHeader.numberOfRelocations: 0x%02x\n"
            "\tsectionHeader.numberOfLineNumbers: 0x%02x\n"
            "\tsectionHeader.characteristics: 0x%04x\n\n"
            ,sectionHeader32[i].name, sectionName, sectionHeader32[i].virtualSize, sectionHeader32[i].virtualAddress, sectionHeader32[i].sizeOfRawData
            ,sectionHeader32[i].pointerToRawData, sectionHeader32[i].pointerToRelocations, sectionHeader32[i].pointerToLineNumbers
            ,sectionHeader32[i].numberOfRelocations, sectionHeader32[i].numberOfLineNumbers, sectionHeader32[i].characteristics);
            free(sectionNameBuf);
        }
    }
    
}


void parsePE32(FILE* pefile, struct switchList* psList){
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));
    
    struct IMAGE_DOS_HEADER32* msDOSHeader = malloc(sizeof(struct IMAGE_DOS_HEADER32));
    if(msDOSHeader == NULL){
    	perror("Failed to allocate memory for msDOSHeader structure");
    	return;
    }
    
    struct IMAGE_COFF_HEADER32* coffHeader = malloc(sizeof(struct IMAGE_COFF_HEADER32));
    if(coffHeader == NULL){
    	perror("Failed to allocate memory for coffHeader structure");
    	return;
    }
    
    coffHeader->machineArchitecture = malloc(31 * sizeof(char));
    if(coffHeader->machineArchitecture == NULL){
    	perror("Failed to allocate memory for coffHeader->machineArchitecture structure");
    	return;
    }
    memcpy(coffHeader->machineArchitecture, "INITIALIZATION_VALUE", 21);
    
    coffHeader->characteristicsList = malloc(17 * sizeof(char*));
    if(coffHeader->characteristicsList == NULL){
    	perror("Failed to allocate memory for coffHeader->characteristicsList structure");
    	return;
    }
	
    for(size_t i=0;i<17;i++){
    	coffHeader->characteristicsList[i] = malloc(32 * sizeof(char));
    	if(coffHeader->characteristicsList[i] == NULL){
    		perror("Failed to allocate memory for coffHeader->characteristicsList structure");
    		return;
    	}
    	memcpy(coffHeader->characteristicsList[i], "INITIALIZATION_VALUE", 21);
    }
    	
    struct IMAGE_OPTIONAL_HEADER32* optionalHeader32 = malloc(sizeof(struct IMAGE_OPTIONAL_HEADER32));
    if(optionalHeader32 == NULL){
    	perror("Failed to allocate memory for optionalHeader32 structure");
    	return;
    }
    
    optionalHeader32->subsystemType = malloc(41 * sizeof(char));
    if(optionalHeader32->subsystemType == NULL){
    	perror("Failed to allocate memory for optionalHeader32->subsystemType structure");
    	return;
    }
    memcpy(optionalHeader32->subsystemType, "SUBSYSTEM_INITIALIZATION_VALUE", 31);
    
    optionalHeader32->dllCharacteristicsList = malloc(16 * sizeof(char*));
    if(optionalHeader32->dllCharacteristicsList == NULL){
    	perror("Failed to allocate memory for optionalHeader32->dllCharacteristicsList structure");
    	return;
    }
    
    for(size_t i=0;i<16;i++){
    	optionalHeader32->dllCharacteristicsList[i] = malloc(47 * sizeof(char));
    	if(optionalHeader32->dllCharacteristicsList[i] == NULL){
    		perror("Failed to allocate memory for optionalHeader32->dllCharacteristicsList structure");
    		return;
    	}
    	memcpy(optionalHeader32->dllCharacteristicsList[i], "DLL_INITIALIZATION_VALUE", 21);
    }
    

    parseMSDOSHeader(pefile, msDOSHeader);
    parseCoffHeader(pefile, convert_DWORD_To_uint32_t(msDOSHeader->e_lfanew), coffHeader);
    parseOptionalHeader32(pefile, convert_DWORD_To_uint32_t(msDOSHeader->e_lfanew), optionalHeader32);
    
    uint16_t numberOfSections = convert_WORD_To_uint16_t(coffHeader->numberOfSections);
    uint32_t memoryOffset = convert_DWORD_To_uint32_t(msDOSHeader->e_lfanew) + 24 + convert_WORD_To_uint16_t(coffHeader->sizeOfOptionalHeader);
    struct SECTION_HEADER32* sectionHeader32 = malloc(numberOfSections * sizeof(struct SECTION_HEADER32));

    if(sectionHeader32 == NULL){
    	perror("Failed to allocate memory for sectionHeader32 structure\n");
    	return;
    }
    
    parseSectionHeaders32(pefile, numberOfSections, memoryOffset, sectionHeader32);
    
    if(!psList->exportResult){
    	consoleOutput32(msDOSHeader, coffHeader, optionalHeader32, sectionHeader32);
    
    if(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[0].virtualAddress) != 0){
    	struct IMAGE_EXPORT_DIRECTORY32* exports32 = malloc(sizeof(struct IMAGE_EXPORT_DIRECTORY32));
        if(exports32 == NULL){
    	    printf("Failed to allocate memory for exports32 structure\n");
    	    return;
        }
        
        uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[0].virtualAddress), numberOfSections, sectionHeader32);
        
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
        
        parseExports32(pefile, diskOffset, numberOfSections, sectionHeader32, exports32, exportFunctionAddresses, exportFunctionNames, exportOrdinalAddresses);
        
        if(!psList->exportResult)
        	exportsConsoleOutput32(pefile, optionalHeader32, exports32, exportFunctionAddresses, exportFunctionNames, exportOrdinalAddresses, numberOfSections, sectionHeader32);
        
        free(exports32);
        free(exportFunctionAddresses);
        free(exportFunctionNames);
        free(exportOrdinalAddresses);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[1].virtualAddress) != 0){
    	struct IMAGE_IMPORT_DESCRIPTOR32** imports32 = malloc(sizeof(struct IMAGE_IMPORT_DESCRIPTOR32*));
    	if(imports32 == NULL){
    	    perror("Failed to allocate memory for imports32 structure\n");
    	    return;
    	}
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[1].virtualAddress), numberOfSections, sectionHeader32);
    	uint32_t tmpDiskOffset = diskOffset;
    	size_t numID=0;
    	
    	struct IMAGE_IMPORT_DESCRIPTOR32* tmpImports32 = malloc(sizeof(struct IMAGE_IMPORT_DESCRIPTOR32));
    	
    	tmpImports32->u.OriginalFirstThunk.u1.ordinal = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    	tmpImports32->timeDateStamp = readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer);
    	tmpImports32->forwarderChain = readDWord(pefile, tmpDiskOffset+8, DWORD_Buffer);
    	tmpImports32->name = readDWord(pefile, tmpDiskOffset+12, DWORD_Buffer);
    	tmpImports32->FirstThunk.u1.addressOfData = readDWord(pefile, tmpDiskOffset+16, DWORD_Buffer);
    	
    	while(!((tmpImports32->u.OriginalFirstThunk.u1.ordinal == 0) && (tmpImports32->timeDateStamp == 0) && (tmpImports32->forwarderChain == 0) && (tmpImports32->name == 0) && (tmpImports32->FirstThunk.u1.addressOfData == 0))){
    		tmpImports32->u.OriginalFirstThunk.u1.ordinal = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    		tmpImports32->timeDateStamp = readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer);
    		tmpImports32->forwarderChain = readDWord(pefile, tmpDiskOffset+8, DWORD_Buffer);
    		tmpImports32->name = readDWord(pefile, tmpDiskOffset+12, DWORD_Buffer);
    		tmpImports32->FirstThunk.u1.addressOfData = readDWord(pefile, tmpDiskOffset+16, DWORD_Buffer);
    		tmpDiskOffset += 20;
    		numID++;
    	}
    	
    	imports32 = realloc(imports32, (numID+1)*sizeof(struct IMAGE_IMPORT_DESCRIPTOR32*));
    	if(imports32 == NULL){
    		perror("Failed to reallocate memory for imports32\n");
    		return;
    	}
    	for(size_t i=0;i<numID;i++){
    		imports32[i] = malloc(sizeof(struct IMAGE_IMPORT_DESCRIPTOR32));
    		if(imports32[i] == NULL){
    			perror("Failed to allocate memory for IMAGE_IMPORT_DESCRIPTOR32\n");
    			return;
    		}	
    	}
    	
    	parseImports32(pefile, numID, diskOffset, numberOfSections, sectionHeader32, imports32);
    	importsConsoleOutput32(pefile, numID, diskOffset, numberOfSections, sectionHeader32, imports32);
    	
    	free(tmpImports32);
    	for(size_t i=0;i<numID;i++)
    		free(imports32[i]);
    	free(imports32);
    }
    
    if((reverse_endianess_uint16_t(optionalHeader32->magic) == 0x20b) && (reverse_endianess_uint32_t(optionalHeader32->dataDirectory[3].virtualAddress) != 0)){
    
        uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[3].virtualAddress), numberOfSections, sectionHeader32);
        uint32_t tmpDiskOffset = diskOffset;
        size_t exceptionCount = 0;
    
        struct IMAGE_EXCEPTION32 tmpexception32;
        
        tmpexception32.startAddress = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
        tmpexception32.endAddress = readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer);
        tmpexception32.unwindAddress = readDWord(pefile, tmpDiskOffset+8, DWORD_Buffer);
        if((tmpexception32.startAddress != 0) && (tmpexception32.endAddress != 0) && (tmpexception32.unwindAddress != 0)){
            tmpDiskOffset += 12;
            exceptionCount++;
        }
            
        while((tmpexception32.startAddress != 0) && (tmpexception32.endAddress != 0) && (tmpexception32.unwindAddress != 0)){
            tmpexception32.startAddress = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
            tmpexception32.endAddress = readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer);
            tmpexception32.unwindAddress = readDWord(pefile, tmpDiskOffset+8, DWORD_Buffer);
            tmpDiskOffset += 12;
            exceptionCount++;
        }
    
    
    	struct IMAGE_EXCEPTION32* exception32 = malloc(exceptionCount * sizeof(struct IMAGE_EXCEPTION32));
    	if(exception32 == NULL){
    	    perror("Failed to allocate memory for exception32");
    	    return;
    	
    	}
    	
    	parseException32(pefile, diskOffset, exceptionCount, exception32);
    	exceptionConsoleOutput32(pefile, diskOffset, exceptionCount, exception32);
    	
    	free(exception32);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[4].virtualAddress) != 0){
        uint32_t diskOffset = reverse_endianess_uint32_t(optionalHeader32->dataDirectory[4].virtualAddress);
        uint32_t tmpDiskOffset = diskOffset;
        size_t certificateCount = 0;
        
        struct IMAGE_CERTIFICATE32 tmpCertificate32;
        tmpCertificate32.dwLength = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
        tmpCertificate32.wRevision = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
        tmpCertificate32.wCertificateType = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
        tmpDiskOffset += reverse_endianess_uint32_t(tmpCertificate32.dwLength);
        while(tmpDiskOffset % 8 != 0)
            tmpDiskOffset++;
        certificateCount++;

        while(tmpDiskOffset < (diskOffset + reverse_endianess_uint32_t(optionalHeader32->dataDirectory[4].size))){
            
            tmpCertificate32.dwLength = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
            tmpCertificate32.wRevision = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
            tmpCertificate32.wCertificateType = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
            tmpDiskOffset += reverse_endianess_uint32_t(tmpCertificate32.dwLength);
            while(tmpDiskOffset % 8 != 0)
            	tmpDiskOffset++;
            certificateCount++;
        }
        
        struct IMAGE_CERTIFICATE32* certificate32 = malloc(certificateCount * sizeof(struct IMAGE_CERTIFICATE32));
        parseCertificate32(pefile, diskOffset, certificateCount, certificate32, optionalHeader32);
        certificateConsoleOutput32(pefile, certificateCount, certificate32);
        free(certificate32);
    
    }
    
    if(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[5].virtualAddress) != 0){
	   struct IMAGE_BASE_RELOCATION32* baseReloc32 = malloc(sizeof(struct IMAGE_BASE_RELOCATION32));
	   if(baseReloc32 == NULL){
		     perror("Failed to allocate memory for baseReloc32");
		     return;
	   }
	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[5].virtualAddress), numberOfSections, sectionHeader32);
    	uint32_t tmpDiskOffset = diskOffset;
    	
    	baseReloc32->pageRVA = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset, DWORD_Buffer));
     	baseReloc32->blockSize = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer));
     	
     	tmpDiskOffset += 8;
     	size_t baseRelocCount = 0;
    	size_t typeCount = 0;
    	
    	while((baseReloc32->pageRVA != 0) && (baseReloc32->blockSize != 0)){
    		baseRelocCount++;
        	typeCount = (baseReloc32->blockSize - 8) / 2;
        	
        	tmpDiskOffset += typeCount * 2;

        	baseReloc32->pageRVA = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset, DWORD_Buffer));
        	baseReloc32->blockSize = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer));
        	tmpDiskOffset += 8;
    	}
    	
    	free(baseReloc32);
    	baseReloc32 = malloc(baseRelocCount * sizeof(struct IMAGE_BASE_RELOCATION32));

    	parseBaseReloc32(pefile, diskOffset, baseRelocCount, baseReloc32);
    	baseRelocConsoleOutput32(pefile, diskOffset, baseRelocCount, baseReloc32);
    	free(baseReloc32);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[6].virtualAddress) != 0){
    	size_t debugCount = reverse_endianess_uint32_t(optionalHeader32->dataDirectory[6].size / sizeof(struct IMAGE_DEBUG_DIRECTORY32));
    	struct IMAGE_DEBUG_DIRECTORY32* debug32 = malloc(debugCount * sizeof(struct IMAGE_DEBUG_DIRECTORY32));
    	if(debug32 == NULL){
    		perror("Failed to allocate memory for debug32");
    		return;
    	}
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[6].virtualAddress), numberOfSections, sectionHeader32);
    	
    	parseDebug32(pefile, debugCount, diskOffset, debug32);
    	debugConsoleOutput32(pefile, debugCount, diskOffset, debug32, sectionHeader32);
    	free(debug32);
    
    }
    
    if(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[9].virtualAddress) != 0){
    	struct IMAGE_TLS_DIRECTORY32* tls32 = malloc(sizeof(struct IMAGE_TLS_DIRECTORY32));
    	if(tls32 == NULL){
    	    perror("Failed to allocate memory for tls32");
    	    return;
    	}
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[9].virtualAddress), numberOfSections, sectionHeader32);
    	parseTLS32(pefile, diskOffset, tls32);
    	free(tls32);
    
    }
    
    
    if(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[10].virtualAddress) != 0){
    	struct IMAGE_LOAD_CONFIG32* loadConfig32 = malloc(sizeof(struct IMAGE_LOAD_CONFIG32));
    	if(loadConfig32 == NULL){
    		perror("Failed to allocate memory for loadConfig32");
    		return;
    	}
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[10].virtualAddress), numberOfSections, sectionHeader32);
    	
    	parseLoadConfig32(pefile, diskOffset, loadConfig32);
    	loadConfigConsoleOutput32(pefile, loadConfig32);
    	free(loadConfig32);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[11].virtualAddress) != 0){
    	struct IMAGE_BOUND_IMPORT_DESCRIPTOR32 tmpBounds32;
    	uint32_t tmpDiskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[11].virtualAddress), numberOfSections, sectionHeader32);
    	size_t boundsCount = 0;
    	
    	tmpBounds32.timestamp = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    	tmpBounds32.offsetModuleName = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
    	tmpBounds32.numberOfModuleForwarderRefs = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
    	boundsCount++;
    	tmpDiskOffset += 8;
    	
    	while((tmpBounds32.timestamp != 0) && (tmpBounds32.offsetModuleName != 0) && (tmpBounds32.numberOfModuleForwarderRefs != 0)){
    		
    		if(tmpBounds32.numberOfModuleForwarderRefs != 0){
    			struct IMAGE_BOUND_FORWARDER_REF32 tmpForwards32;
    			while((tmpForwards32.timestamp != 0) && (tmpForwards32.offsetModuleName != 0) && (tmpForwards32.reserved != 0)){
    				tmpForwards32.timestamp = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    				tmpForwards32.offsetModuleName = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
    				tmpForwards32.reserved = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
    				tmpDiskOffset += 8;
    			}
    		}
    		
    		boundsCount++;
    		tmpDiskOffset += 8;
    		
    		tmpBounds32.timestamp = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    		tmpBounds32.offsetModuleName = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
    		tmpBounds32.numberOfModuleForwarderRefs = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
    	}
    	
    	struct IMAGE_BOUND_IMPORT_DESCRIPTOR32* bounds32 = malloc(boundsCount * sizeof(struct IMAGE_BOUND_IMPORT_DESCRIPTOR32));
    	if(bounds32 == NULL){
    		perror("Failed to allocate memory for bounds32");
    		return;
    	}
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[11].virtualAddress), numberOfSections, sectionHeader32);
    	parseBoundImport32(pefile, diskOffset, boundsCount, bounds32);
    	boundsConsoleOutput32(pefile, diskOffset, boundsCount, bounds32);
    	
    	free(bounds32);
    }
    	
    for(size_t i=0;i<17;i++)
    	free(coffHeader->characteristicsList[i]);
    	
    for(size_t i=0;i<16;i++)
    	free(optionalHeader32->dllCharacteristicsList[i]);
	
    free(msDOSHeader);
    free(coffHeader->machineArchitecture);
    free(coffHeader->characteristicsList);
    free(coffHeader);
    free(optionalHeader32->subsystemType);
    free(optionalHeader32->dllCharacteristicsList);
    free(optionalHeader32);
    free(sectionHeader32);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);

 }

}

#endif
