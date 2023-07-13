#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

typedef u_int8_t BYTE;
typedef u_int16_t WORD;
typedef u_int32_t DWORD;
typedef u_int64_t QWORD;
typedef BYTE *LPBYTE;
typedef WORD *PDWORD;

typedef struct _GUID {
  DWORD Data1;
  WORD Data2;
  WORD Data3;
  BYTE Data4[8];
} GUID;

typedef struct _IMAGE_DOS_HEADER{
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
} imageDOSHeader;

typedef struct _IMAGE_COFF_HEADER{
    DWORD peSignature;
    WORD machine;
    WORD numberOfSections;
    DWORD timeDateStamp;
    DWORD pointerToSymbolTable;
    DWORD numberOfSymbols;
    WORD sizeOfOptionalHeader;
    WORD characteristics;
} imageCOFFHeader;

typedef struct _IMAGE_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} IMAGE_DATA_DIRECTORY;

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

typedef struct _IMAGE_OPTIONAL_HEADER32{
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
    IMAGE_DATA_DIRECTORY dataDirectory[16];
} imageOptionalHeader32;

typedef struct _IMAGE_OPTIONAL_HEADER64{
    WORD magic;
    BYTE majorLinkerVersion;
    BYTE minorLinkerVersion;
    DWORD sizeOfCode;
    DWORD sizeOfInitializedData;
    DWORD sizeOfUninitializedData;
    DWORD addressOfEntryPoint;
    DWORD baseOfCode;
    QWORD imageBase;
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
    QWORD sizeOfStackReserve;
    QWORD sizeOfStackCommit;
    QWORD sizeOfHeapReserve;
    QWORD sizeOfHeapCommit;
    DWORD loaderFlags;
    DWORD numberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY dataDirectory[16];
} imageoptionalHeader64;


typedef struct _EXPORT_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} exportDataDirectory;

typedef struct _IMAGE_EXPORT_DIRECTORY{
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
} imageExportDirectory;

typedef struct _IMPORT_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} importDataDirectory;

typedef struct _IMAGE_IMPORT_BY_NAME{
    WORD hint;
    BYTE name;
} IMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA32{
    union{
        DWORD forwarderString;
        DWORD function;
        DWORD ordinal;
        DWORD addressOfData;
    } u1;
} IMAGE_THUNK_DATA32;

typedef struct _IMAGE_THUNK_DATA64{
    union{
        QWORD forwarderString;
        QWORD function;
        QWORD ordinal;
        QWORD addressOfData;
    } u1;
} IMAGE_THUNK_DATA64;

struct _IMAGE_IMPORT_DESCRIPTOR32{
    union{
        DWORD Characteristics;
        IMAGE_THUNK_DATA32 OriginalFirstThunk;
    } u;
    DWORD timeDateStamp;
    DWORD forwarderChain;
    DWORD name;
    IMAGE_THUNK_DATA32 FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR32;

struct _IMAGE_IMPORT_DESCRIPTOR64{
    union{
        DWORD Characteristics;
        IMAGE_THUNK_DATA32 OriginalFirstThunk;
    } u;
    DWORD timeDateStamp;
    DWORD forwarderChain;
    DWORD name;
    IMAGE_THUNK_DATA32 FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR64;

typedef struct _IMAGE_RESOURCE_DIRECTORY{
    DWORD characteristics;
    DWORD timeDateStamp;
    WORD majorVersion;
    WORD minorVersion;
    WORD numberOfNamedEntries;
    WORD numberOfIdEntries; 
} IMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY{
    DWORD nameOffset;
    DWORD id;
} IMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA{
    DWORD dataRVA;
    DWORD size;
    DWORD codepage;
    DWORD reserved;
} IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA;


typedef struct _RESOURCE_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} resourceDataDirectory;

typedef struct _IMAGE_EXCEPTION{
    DWORD startAddress;
    DWORD endAddress;
    DWORD unwindAddress;
} imageException;

typedef struct _EXCEPTION_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} exceptionDataDirectory;

typedef struct _CERTIFICATE_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} certificateDataDirectory;

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


typedef struct _IMAGE_BASE_RELOCATION{
  DWORD pageRVA;
  DWORD blockSize;
} imageBaseReloc;

typedef struct _BASE_RELOCATION_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} baseRelocationDataDirectory;

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

typedef struct _DEBUG_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} debugDataDirectory;

typedef struct _IMAGE_DEBUG_DIRECTORY{
  DWORD characteristics;
  DWORD timeDateStamp;
  WORD  majorVersion;
  WORD  minorVersion;
  DWORD type;
  DWORD sizeOfData;
  DWORD addressOfRawData;
  DWORD pointerToRawData;
} IMAGE_DEBUG_DIRECTORY;

typedef struct _CV_HEADER
{
  DWORD Signature;
  DWORD Offset;
} CV_HEADER;

struct _CV_INFO_PDB20{
  CV_HEADER header;
  DWORD offset;
  DWORD signature;
  DWORD age;
  BYTE pdbFileName;
}CV_INFO_PDB20;

struct _CV_INFO_PDB70{
  DWORD  cvSignature;
  GUID signature;
  DWORD age;
  BYTE pdbFileName;
}CV_INFO_PDB70;

typedef struct _ARCHITECTURE_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} architectureDataDirectory;

typedef struct _GLOBAL_PTR_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} globalPtrDataDirectory;

typedef struct _IMAGE_TLS_DIRECTORY32{
  DWORD startAddressOfRawData;
  DWORD endAddressOfRawData;
  DWORD addressOfIndex;
  DWORD addressOfCallBacks;
  DWORD sizeOfZeroFill;
  DWORD characteristics;
} imagetlsdirectory32;

typedef struct _IMAGE_TLS_DIRECTORY64{
  QWORD startAddressOfRawData;
  QWORD endAddressOfRawData;
  QWORD addressOfIndex;
  QWORD addressOfCallBacks;
  DWORD sizeOfZeroFill;
  DWORD characteristics;
} imagetlsdirectory64; 

typedef struct _TLS_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} tlsDataDirectory;

typedef struct _IMAGE_LOAD_CONFIG32{
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
}imageLoadConfig32;

typedef struct _IMAGE_LOAD_CONFIG64{
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
}imageLoadConfig64;

typedef struct _LOAD_CONFIG_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} loadConfigDataDirectory;

typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR{
    DWORD timestamp;
    WORD offsetModuleName;
    WORD numberOfModuleForwarderRefs;
} IMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BOUND_FORWARDER_REF{
    DWORD timestamp;
    WORD offsetModuleName;
    WORD reserved;
} IMAGE_BOUND_FORWARDER_REF;

typedef struct _BOUND_IMPORT_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} boundImportDataDirectory;

typedef struct _IAT_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} iatDataDirectory;

typedef struct ImgDelayDescr {
    DWORD  grAttrs;
    DWORD  rvaDLLName;
    DWORD  rvaHmod;
    DWORD  rvaIAT;
    DWORD  rvaINT;
    DWORD  rvaBoundIAT;
    DWORD  rvaUnloadIAT;
    DWORD  dwTimeStamp;
} imgDelayDescr;

typedef struct _DELAY_IMPORT_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} delayImportDataDirectory;

typedef struct _CLR_RUNTIME_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} clrRuntimeDataDirectory;

typedef struct _RESERVED_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
} reservedDataDirectory;

typedef struct _SECTION_HEADER{
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
} sectionHeader;

extern u_int8_t reverse_endianess_u_int8_t(u_int8_t value);
extern u_int16_t reverse_endianess_u_int16_t(u_int16_t value);
extern u_int32_t reverse_endianess_u_int32_t(u_int32_t value);
extern u_int32_t reverse_endianess_u_int32_t(u_int32_t value);
extern u_int64_t reverse_endianess_u_int64_t(u_int64_t value);
extern u_int8_t readByte(FILE* file, size_t offset, u_int8_t* buffer);
extern u_int16_t readWord(FILE* file, size_t offset, u_int16_t* buffer);
extern u_int32_t readDWord(FILE* file, size_t offset, u_int32_t* buffer);
extern u_int64_t readQWord(FILE* file, size_t offset, u_int64_t* buffer);
struct _IMAGE_DOS_HEADER parseMSDOSHeader(FILE* file);
struct _IMAGE_COFF_HEADER parseCoffHeader(FILE* file, u_int32_t elfanew);
char* getMachineArchitecture(u_int16_t machine);
char** getCharacteristics(u_int16_t characteristics);
struct _IMAGE_OPTIONAL_HEADER32 parseOptionalHeader32(FILE* file, u_int32_t elfanew);
struct _IMAGE_OPTIONAL_HEADER64 parseOptionalHeader64(FILE* file, u_int32_t elfanew);
char* getSubsystem(u_int16_t subsystem);
char** getDllCharacteristics(u_int16_t dllCharacteristics);
void parseSectionHeaders32(FILE* file, u_int16_t numberOfSections, u_int16_t sizeOfOptionalHeader, u_int32_t elfanew, struct _SECTION_HEADER sectionHeader32[]);
void parseSectionHeaders64(FILE* file, u_int16_t numberOfsections, u_int16_t sizeOfOptionalHeader, u_int32_t elfanew, struct _SECTION_HEADER sectionHeader64[]);
unsigned char hexdigit2int(unsigned char xd);
u_int16_t convert_WORD_To_u_int16_t(WORD structureValue);
void parseExportDirectory32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], bool consoleOutput);
void parseExportDirectory64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], bool consoleOutput);
void parseImportDirectory32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], bool consoleOutput);
void parseImportDirectory64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], bool consoleOutput);
void parseRDirectory32(FILE* file, u_int32_t resourceDirectoryOffset, u_int32_t pointerToRawData, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[]);
void parseRDirectory64(FILE* file, u_int32_t resourceDirectoryOffset, u_int32_t pointerToRawData, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[]);
void parseResourceDirectory32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput);
void parseResourceDirectory64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader64[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput);
void parseDebugDirectory32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], bool consoleOutput);
void parseDebugDirectory64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], bool consoleOutput);
void parseBaseRelocations32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput);
void parseBaseRelocations64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader64[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput);
void parseLoadConfig32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput);
void parseLoadConfig64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader64[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput);
void consoleOutput32(struct _IMAGE_DOS_HEADER dosHeader, struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, struct _SECTION_HEADER sectionHeader32[], FILE* file);
void consoleOutput64(struct _IMAGE_DOS_HEADER dosHeader, struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, struct _SECTION_HEADER sectionHeader64[], FILE* file);
char* convert_u_int64_t_ToString(u_int64_t numericalValue, char computedString[4096]);
extern void parsePE(char* pathOfSpecifiedFile, bool exportResult);

u_int8_t reverse_endianess_u_int8_t(u_int8_t value){
    u_int8_t resultat = 0;
    char *source, *destination;
    u_int8_t i;

    source = (char *) &value;
    destination = ((char *) &resultat) + sizeof(u_int8_t);
    for (i = 0; i < sizeof(u_int8_t); i++)
        *(--destination) = *(source++);

    return resultat;
}

u_int16_t reverse_endianess_u_int16_t(u_int16_t value) {
    u_int16_t resultat = 0;
    char *source, *destination;
    u_int16_t i;

    source = (char *) &value;
    destination = ((char *) &resultat) + sizeof(u_int16_t);
    for (i = 0; i < sizeof(u_int16_t); i++)
        *(--destination) = *(source++);

    return resultat;
}

u_int32_t reverse_endianess_u_int32_t(u_int32_t value) {
    u_int32_t resultat = 0;
    char *source, *destination;
    u_int32_t i;

    source = (char *) &value;
    destination = ((char *) &resultat) + sizeof(u_int32_t);
    for (i = 0; i < sizeof(u_int32_t); i++)
        *(--destination) = *(source++);

    return resultat;
}

u_int64_t reverse_endianess_u_int64_t(u_int64_t value) {
    u_int64_t resultat = 0;
    char *source, *destination;
    u_int64_t i;

    source = (char *) &value;
    destination = ((char *) &resultat) + sizeof(u_int64_t);
    for (i = 0; i < sizeof(u_int64_t); i++)
        *(--destination) = *(source++);
        
    return resultat;
}

u_int8_t readByte(FILE* file, size_t offset, u_int8_t* buffer){
    size_t fReadSuccess;

    if(fseek(file, offset, SEEK_SET)){
       perror("FATAL ERROR: Failed to seek to the specified file offset.\n"); 
    }
    else{
        fReadSuccess = fread(buffer, 0x01, 0x01, file); //buffer, size, count, stream
        if(fReadSuccess == 0x01){
            return reverse_endianess_u_int8_t(*buffer);
        }
        else{
            printf("FATAL ERROR: Failed to read appropriate countOfObjects in readByte.\n");
        }
    }

    return 0;
}

u_int16_t readWord(FILE* file, size_t offset, u_int16_t* buffer){
    size_t fReadSuccess;

    if(fseek(file, offset, SEEK_SET)){
       perror("FATAL ERROR: Failed to seek to the specified file offset.\n"); 
    }
    else{
        fReadSuccess = fread(buffer, 0x01, 0x02, file); //buffer, size, count, stream
        if(fReadSuccess == 0x02){
            return reverse_endianess_u_int16_t(*buffer);
        }
        else{
            printf("FATAL ERROR: Failed to read appropriate countOfObjects in readWord.\n");
        }
    }

    return 0;
}

u_int32_t readDWord(FILE* file, size_t offset, u_int32_t* buffer){
    size_t fReadSuccess;

    if(fseek(file, offset, SEEK_SET)){
       perror("FATAL ERROR: Failed to seek to the specified file offset.\n"); 
    }
    else{
        fReadSuccess = fread(buffer, 0x01, 0x04, file); //buffer, size, count, stream
        if(fReadSuccess == 0x04){
            return reverse_endianess_u_int32_t(*buffer);
        }
        else{
            printf("FATAL ERROR: Failed to read appropriate countOfObjects in readDWord.\n");
        }
    }

    return 0;
}

u_int64_t readQWord(FILE* file, size_t offset, u_int64_t* buffer){
    size_t fReadSuccess;

    if(fseek(file, offset, SEEK_SET)){
       perror("FATAL ERROR: Failed to seek to the specified file offset.\n"); 
    }
    else{
        fReadSuccess = fread(buffer, 0x01, 0x08, file); //buffer, size, count, stream
        if(fReadSuccess == 0x08){
            return reverse_endianess_u_int64_t(*buffer);
        }
        else{
            printf("FATAL ERROR: Failed to read appropriate countOfObjects in readQWord.\n");
        }
    }

    return 0;
}


struct _IMAGE_DOS_HEADER parseMSDOSHeader(FILE* file){
    struct _IMAGE_DOS_HEADER dosHeader;
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    size_t j = 0;

    dosHeader.e_magic = readWord(file, 0x00, WORD_Buffer);
    dosHeader.e_cblp = readWord(file, 0x02, WORD_Buffer);
    dosHeader.e_cp = readWord(file, 0x04, WORD_Buffer);
    dosHeader.e_crlc = readWord(file, 0x06, WORD_Buffer);
    dosHeader.e_cparhdr = readWord(file, 0x08, WORD_Buffer);
    dosHeader.e_minalloc = readWord(file, 0x0A, WORD_Buffer);
    dosHeader.e_maxalloc = readWord(file, 0x0C, WORD_Buffer);
    dosHeader.e_ss = readWord(file, 0x0E, WORD_Buffer);
    dosHeader.e_sp = readWord(file, 0x10, WORD_Buffer);
    dosHeader.e_csum = readWord(file, 0x12, WORD_Buffer);
    dosHeader.e_ip = readWord(file, 0x14, WORD_Buffer);
    dosHeader.e_cs = readWord(file, 0x16, WORD_Buffer);
    dosHeader.e_lfarlc = readWord(file, 0x18, WORD_Buffer);
    dosHeader.e_ovno = readWord(file, 0x1A, WORD_Buffer);
    
    for(size_t i=0x1C;i<0x24;i+=0x02){
        dosHeader.e_res[j++] = readWord(file, i, WORD_Buffer);
    }

    dosHeader.e_oemid = readWord(file, 0x24, WORD_Buffer);
    
    j=0;
    for(size_t i=0x26;i<0x3C;i+=0x02){
        dosHeader.e_res2[j++] = readWord(file, i, WORD_Buffer);
    }

    dosHeader.e_lfanew = readDWord(file, 0x3C, DWORD_Buffer);

    free(WORD_Buffer);
    free(DWORD_Buffer);
    return dosHeader;
}

struct _IMAGE_COFF_HEADER parseCoffHeader(FILE* file, u_int32_t elfanew){
    static struct _IMAGE_COFF_HEADER coffHeader;
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));

    coffHeader.peSignature = readDWord(file, elfanew, DWORD_Buffer);
    coffHeader.machine = readWord(file, elfanew+04, WORD_Buffer);
    coffHeader.numberOfSections = readWord(file, elfanew+6, WORD_Buffer);
    coffHeader.timeDateStamp = readDWord(file, elfanew+8, DWORD_Buffer);
    coffHeader.pointerToSymbolTable = readDWord(file, elfanew+12, DWORD_Buffer);
    coffHeader.numberOfSymbols = readDWord(file, elfanew+16, DWORD_Buffer);
    coffHeader.sizeOfOptionalHeader = readWord(file, elfanew+20, WORD_Buffer);
    coffHeader.characteristics = readWord(file, elfanew+22, WORD_Buffer);

    free(WORD_Buffer);
    free(DWORD_Buffer);
    return coffHeader;
}

char* getMachineArchitecture(u_int16_t machine){
    switch(machine){
        case 0x0:
            return "IMAGE_FILE_MACHINE_UNKNOWN";
        case 0x1d3:
            return "IMAGE_FILE_MACHINE_AM33";
        case 0x8664:
            return "IMAGE_FILE_MACHINE_AMD64";
        case 0x1c0:
            return "IMAGE_FILE_MACHINE_ARM";
        case 0xaa64:
            return "IMAGE_FILE_MACHINE_ARM64";
        case 0x1c4:
            return "IMAGE_FILE_MACHINE_ARMNT";
        case 0xebc:
            return "IMAGE_FILE_MACHINE_EBC";
        case 0x14c:
            return "IMAGE_FILE_MACHINE_I386";
        case 0x200:
            return "IMAGE_FILE_MACHINE_IA64";
        case 0x6232:
            return "IMAGE_FILE_MACHINE_LOONGARCH32";
        case 0x6264:
            return "IMAGE_FILE_MACHINE_LOONGARCH64";
        case 0x9041:
            return "IMAGE_FILE_MACHINE_M32R";
        case 0x266:
            return "IMAGE_FILE_MACHINE_MIPS16";
        case 0x366:
            return "IMAGE_FILE_MACHINE_MIPSFPU";
        case 0x1f0:
            return "IMAGE_FILE_MACHINE_POWERPC";
        case 0x1f1:
            return "IMAGE_FILE_MACHINE_POWERPCFP";
        case 0x166:
            return "IMAGE_FILE_MACHINE_R4000";
        case 0x5032:
            return "IMAGE_FILE_MACHINE_RISCV32";
        case 0x5064:
            return "IMAGE_FILE_MACHINE_RISCV64";
        case 0x5128:
            return "IMAGE_FILE_MACHINE_RISCV128";
        case 0x1a2:
            return "IMAGE_FILE_MACHINE_SH3";
        case 0x1a3:
            return "IMAGE_FILE_MACHINE_SH3DSP";
        case 0x1a6:
            return "IMAGE_FILE_MACHINE_SH4";
        case 0x1a8:
            return "IMAGE_FILE_MACHINE_SH5";
        case 0x1c2:
            return "IMAGE_FILE_MACHINE_THUMB";
        case 0x169:
            return "IMAGE_FILE_MACHINE_WCEMIPSV2";
        default:
            return "UNDEFINED_ARCHITECTURE_ANOMALY";
    }
}

char** getCharacteristics(u_int16_t characteristics){
    char** characteristicsArray = calloc(16, sizeof(char*));
    int imageFileCharacteristics[16] = {1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768};
    int* savedCharacteristics = calloc(16, sizeof(int));
    size_t j=0;

    for(int i=15;i>=0;i--){
        if(((characteristics - imageFileCharacteristics[i]) >= 0) && (characteristics!=0)){
            savedCharacteristics[j++] = imageFileCharacteristics[i];
            characteristics -= imageFileCharacteristics[i];
        }
    }

    for(size_t i=0;i<j;i++){
        switch(savedCharacteristics[i]){
            case 1:
                characteristicsArray[i] = "IMAGE_FILE_RELOCS_STRIPPED";
                break;
            case 2:
                characteristicsArray[i] = "IMAGE_FILE_EXECUTABLE_IMAGE";
                break;
            case 4:
                characteristicsArray[i] = "IMAGE_FILE_LINE_NUMS_STRIPPED";
                break;
            case 8:
                characteristicsArray[i] = "IMAGE_FILE_LOCAL_SYMS_STRIPPED";
                break;
            case 16:
                characteristicsArray[i] = "IMAGE_FILE_AGGRESSIVE_WS_TRIM";
                break;
            case 32:
                characteristicsArray[i] = "IMAGE_FILE_LARGE_ADDRESS_AWARE";
                break;
            case 64:
                characteristicsArray[i] = "IMAGE_FILE_FUTURE_USE";
                break;
            case 128:
                characteristicsArray[i] = "IMAGE_FILE_BYTES_REVERSED_LO";
                break;
            case 256:
                characteristicsArray[i] = "IMAGE_FILE_32BIT_MACHINE";
                break;
            case 512:
                characteristicsArray[i] = "IMAGE_FILE_DEBUG_STRIPPED";
                break;
            case 1024:
                characteristicsArray[i] = "IMAGE_FILE_REMOVABLE_RUN_";
                break;
            case 2048:
                characteristicsArray[i] = "IMAGE_FILE_NET_RUN_FROM_SWAP";
                break;
            case 4096:
                characteristicsArray[i] = "IMAGE_FILE_SYSTEM";
                break;
            case 8192:
                characteristicsArray[i] = "IMAGE_FILE_DLL";
                break;
            case 16384:
                characteristicsArray[i] = "IMAGE_FILE_UP_SYSTEM_ONLY";
                break;
            case 32768:
                characteristicsArray[i] = "IMAGE_FILE_BYTES_REVERSED_HI";
                break;
            default:
                characteristicsArray[i] = "UNKNOWN_CHARACTERISTICS_ANOMALY";
        }
    }

    return characteristicsArray;
}

struct _IMAGE_OPTIONAL_HEADER32 parseOptionalHeader32(FILE* file, u_int32_t elfanew){
    static struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32;
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));

    optionalHeader32.magic = readWord(file, elfanew+24, WORD_Buffer);
    optionalHeader32.majorLinkerVersion = readByte(file, elfanew+26, BYTE_Buffer);
    optionalHeader32.minorLinkerVersion = readByte(file, elfanew+27, BYTE_Buffer);
    optionalHeader32.sizeOfCode = readDWord(file, elfanew+28, DWORD_Buffer);
    optionalHeader32.sizeOfInitializedData = readDWord(file, elfanew+32, DWORD_Buffer);
    optionalHeader32.sizeOfUninitializedData = readDWord(file, elfanew+36, DWORD_Buffer);
    optionalHeader32.addressOfEntryPoint = readDWord(file, elfanew+40, DWORD_Buffer);
    optionalHeader32.baseOfCode = readDWord(file, elfanew+44, DWORD_Buffer);
    optionalHeader32.baseOfData = readDWord(file, elfanew+48, DWORD_Buffer);
    optionalHeader32.imageBase = readDWord(file, elfanew+52, DWORD_Buffer);
    optionalHeader32.sectionAlignment = readDWord(file, elfanew+56, DWORD_Buffer);
    optionalHeader32.fileAlignment = readDWord(file, elfanew+60, DWORD_Buffer);
    optionalHeader32.majorOperatingSystemVersion = readWord(file, elfanew+64, WORD_Buffer);
    optionalHeader32.minorOperatingSystemVersion = readWord(file, elfanew+66, WORD_Buffer);
    optionalHeader32.majorImageVersion = readWord(file, elfanew+68, WORD_Buffer);
    optionalHeader32.minorImageVersion = readWord(file, elfanew+70, WORD_Buffer);
    optionalHeader32.majorSubsystemVersion = readWord(file, elfanew+72, WORD_Buffer);
    optionalHeader32.minorSubsystemVersion = readWord(file, elfanew+74, WORD_Buffer);
    optionalHeader32.win32VersionValue = readDWord(file, elfanew+76, DWORD_Buffer);
    optionalHeader32.sizeOfImage = readDWord(file, elfanew+80, DWORD_Buffer);
    optionalHeader32.sizeOfHeaders = readDWord(file, elfanew+84, DWORD_Buffer);
    optionalHeader32.checksum = readDWord(file, elfanew+88, DWORD_Buffer);
    optionalHeader32.subsystem = readWord(file, elfanew+92, WORD_Buffer);
    optionalHeader32.dllCharacteristics = readWord(file, elfanew+94, WORD_Buffer);
    optionalHeader32.sizeOfStackReserve = readDWord(file, elfanew+96, DWORD_Buffer);
    optionalHeader32.sizeOfStackCommit = readDWord(file, elfanew+100, DWORD_Buffer);
    optionalHeader32.sizeOfHeapReserve = readDWord(file, elfanew+104, DWORD_Buffer);
    optionalHeader32.sizeOfHeapCommit = readDWord(file, elfanew+108, DWORD_Buffer);
    optionalHeader32.loaderFlags = readDWord(file, elfanew+112, DWORD_Buffer);
    optionalHeader32.numberOfRvaAndSizes = readDWord(file, elfanew+116, DWORD_Buffer);

    size_t j = 0;
    size_t maxDirectories = reverse_endianess_u_int32_t(optionalHeader32.numberOfRvaAndSizes);
    for(size_t i=0;i<maxDirectories;i++){
        optionalHeader32.dataDirectory[i].virtualAddress = readDWord(file, elfanew+120+j, DWORD_Buffer);
        j+=4;
        optionalHeader32.dataDirectory[i].size = readDWord(file, elfanew+120+j, DWORD_Buffer);
        j+=4;
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    return optionalHeader32;
}

struct _IMAGE_OPTIONAL_HEADER64 parseOptionalHeader64(FILE* file, u_int32_t elfanew){
    static struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64;
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int64_t* QWORD_Buffer = calloc(8, sizeof(u_int8_t));

    optionalHeader64.magic = readWord(file, elfanew+24, WORD_Buffer);
    optionalHeader64.majorLinkerVersion = readByte(file, elfanew+26, BYTE_Buffer);
    optionalHeader64.minorLinkerVersion = readByte(file, elfanew+27, BYTE_Buffer);
    optionalHeader64.sizeOfCode = readDWord(file, elfanew+28, DWORD_Buffer);
    optionalHeader64.sizeOfInitializedData = readDWord(file, elfanew+32, DWORD_Buffer);
    optionalHeader64.sizeOfUninitializedData = readDWord(file, elfanew+36, DWORD_Buffer);
    optionalHeader64.addressOfEntryPoint = readDWord(file, elfanew+40, DWORD_Buffer);
    optionalHeader64.baseOfCode = readDWord(file, elfanew+44, DWORD_Buffer);
    optionalHeader64.imageBase = readQWord(file, elfanew+48, QWORD_Buffer);
    optionalHeader64.sectionAlignment = readDWord(file, elfanew+56, DWORD_Buffer);
    optionalHeader64.fileAlignment = readDWord(file, elfanew+60, DWORD_Buffer);
    optionalHeader64.majorOperatingSystemVersion = readWord(file, elfanew+64, WORD_Buffer);
    optionalHeader64.minorOperatingSystemVersion = readWord(file, elfanew+66, WORD_Buffer);
    optionalHeader64.majorImageVersion = readWord(file, elfanew+68, WORD_Buffer);
    optionalHeader64.minorImageVersion = readWord(file, elfanew+70, WORD_Buffer);
    optionalHeader64.majorSubsystemVersion = readWord(file, elfanew+72, WORD_Buffer);
    optionalHeader64.minorSubsystemVersion = readWord(file, elfanew+74, WORD_Buffer);
    optionalHeader64.win32VersionValue = readDWord(file, elfanew+76, DWORD_Buffer);
    optionalHeader64.sizeOfImage = readDWord(file, elfanew+80, DWORD_Buffer);
    optionalHeader64.sizeOfHeaders = readDWord(file, elfanew+84, DWORD_Buffer);
    optionalHeader64.checksum = readDWord(file, elfanew+88, DWORD_Buffer);
    optionalHeader64.subsystem = readWord(file, elfanew+92, WORD_Buffer);
    optionalHeader64.dllCharacteristics = readWord(file, elfanew+94, WORD_Buffer);
    optionalHeader64.sizeOfStackReserve = readQWord(file, elfanew+96, QWORD_Buffer);
    optionalHeader64.sizeOfStackCommit = readQWord(file, elfanew+104, QWORD_Buffer);
    optionalHeader64.sizeOfHeapReserve = readQWord(file, elfanew+112, QWORD_Buffer);
    optionalHeader64.sizeOfHeapCommit = readQWord(file, elfanew+120, QWORD_Buffer);
    optionalHeader64.loaderFlags = readDWord(file, elfanew+128, DWORD_Buffer);
    optionalHeader64.numberOfRvaAndSizes = readDWord(file, elfanew+132, DWORD_Buffer);

    size_t j = 0;
    size_t maxDirectories = reverse_endianess_u_int32_t(optionalHeader64.numberOfRvaAndSizes);
    for(size_t i=0;i<maxDirectories;i++){
        optionalHeader64.dataDirectory[i].virtualAddress = readDWord(file, elfanew+136+j, DWORD_Buffer);
        j+=4;
        optionalHeader64.dataDirectory[i].size = readDWord(file, elfanew+136+j, DWORD_Buffer);
        j+=4;
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    return optionalHeader64;
}

char* getSubsystem(u_int16_t subsystem){
    switch(subsystem){
        case 0:
            return "IMAGE_SUBSYSTEM_UNKNOWN";
        case 1:
            return "IMAGE_SUBSYSTEM_NATIVE";
        case 2:
            return "IMAGE_SUBSYSTEM_WINDOWS_GUI";
        case 3:
            return "IMAGE_SUBSYSTEM_WINDOWS_CUI";
        case 5:
            return "IMAGE_SUBSYSTEM_OS2_CUI";
        case 7:
            return "IMAGE_SUBSYSTEM_POSIX_CUI";
        case 8:
            return "IMAGE_SUBSYSTEM_NATIVE_WINDOWS";
        case 9:
            return "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
        case 10:
            return "IMAGE_SUBSYSTEM_EFI_APPLICATION";
        case 11:
            return "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER";
        case 12:
            return "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER";
        case 13:
            return "IMAGE_SUBSYSTEM_EFI_ROM";
        case 14:
            return "IMAGE_SUBSYSTEM_XBOX";
        case 16:
            return "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION";
        default:
            return "UNDEFINED_IMAGE_SUBSYSTEM_ANOMALY";
    }
}

char** getDllCharacteristics(u_int16_t dllCharacteristics){
    char** characteristicsArray = calloc(16, sizeof(char*));
    int imageFileCharacteristics[16] = {1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768};
    int* savedCharacteristics = calloc(16, sizeof(int));
    size_t j=0;

    for(int i=15;i>=0;i--){
        if(((dllCharacteristics - imageFileCharacteristics[i]) >= 0) && (dllCharacteristics!=0)){
            savedCharacteristics[j++] = imageFileCharacteristics[i];
            dllCharacteristics -= imageFileCharacteristics[i];
        }
    }


    for(size_t i=0;i<j;i++){
        switch(savedCharacteristics[i]){
            case 32:
                characteristicsArray[i] = "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA";
                break;
            case 64:
                characteristicsArray[i] = "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE";
                break;
            case 128:
                characteristicsArray[i] = "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY";
                break;
            case 256:
                characteristicsArray[i] = "IMAGE_DLLCHARACTERISTICS_NX_COMPAT";
                break;
            case 512:
                characteristicsArray[i] = "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION";
                break;
            case 1024:
                characteristicsArray[i] = "IMAGE_DLLCHARACTERISTICS_NO_SEH";
                break;
            case 2048:
                characteristicsArray[i] = "IMAGE_DLLCHARACTERISTICS_NO_BIND";
                break;
            case 4096:
                characteristicsArray[i] = "IMAGE_DLLCHARACTERISTICS_APPCONTAINER";
                break;
            case 8192:
                characteristicsArray[i] = "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER";
                break;
            case 16384:
                characteristicsArray[i] = "IMAGE_DLLCHARACTERISTICS_GUARD_CF";
                break;
            case 32768:
                characteristicsArray[i] = "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE";
                break;
            default:
                characteristicsArray[i] = "UNKNOWN_DLL_CHARACTERISTICS_ANOMALY";
        }
    }

    return characteristicsArray;
}

void parseSectionHeaders32(FILE* file, u_int16_t numberOfSections, u_int16_t sizeOfOptionalHeader, u_int32_t elfanew, struct _SECTION_HEADER sectionHeader32[]){
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int64_t* QWORD_Buffer = calloc(8, sizeof(u_int8_t));
    u_int32_t memoryOffset = elfanew + 24 + sizeOfOptionalHeader;

    for(size_t i=0; i<numberOfSections; i++){
        sectionHeader32[i].name = readQWord(file, memoryOffset+i*40, QWORD_Buffer);
        sectionHeader32[i].virtualSize = readDWord(file, memoryOffset+i*40+8, DWORD_Buffer);
        sectionHeader32[i].virtualAddress = readDWord(file, memoryOffset+i*40+12, DWORD_Buffer);
        sectionHeader32[i].sizeOfRawData = readDWord(file, memoryOffset+i*40+16, DWORD_Buffer);
        sectionHeader32[i].pointerToRawData = readDWord(file, memoryOffset+i*40+20, DWORD_Buffer);
        sectionHeader32[i].pointerToRelocations = readDWord(file, memoryOffset+i*40+24, DWORD_Buffer);
        sectionHeader32[i].pointerToLineNumbers = readDWord(file, memoryOffset+i*40+28, DWORD_Buffer);
        sectionHeader32[i].numberOfRelocations = readWord(file, memoryOffset+i*40+32, WORD_Buffer);
        sectionHeader32[i].numberOfLineNumbers = readWord(file, memoryOffset+i*40+34, WORD_Buffer);
        sectionHeader32[i].characteristics = readDWord(file, memoryOffset+i*40+36, DWORD_Buffer);
    }
}

void parseSectionHeaders64(FILE* file, u_int16_t numberOfsections, u_int16_t sizeOfOptionalHeader, u_int32_t elfanew, struct _SECTION_HEADER sectionHeader64[]){
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int64_t* QWORD_Buffer = calloc(8, sizeof(u_int8_t));
    u_int32_t memoryOffset = elfanew + 24 + sizeOfOptionalHeader;

    for(size_t i=0; i<numberOfsections; i++){
        sectionHeader64[i].name = readQWord(file, memoryOffset+i*40, QWORD_Buffer);
        sectionHeader64[i].virtualSize = readDWord(file, memoryOffset+i*40+8, DWORD_Buffer);
        sectionHeader64[i].virtualAddress = readDWord(file, memoryOffset+i*40+12, DWORD_Buffer);
        sectionHeader64[i].sizeOfRawData = readDWord(file, memoryOffset+i*40+16, DWORD_Buffer);
        sectionHeader64[i].pointerToRawData = readDWord(file, memoryOffset+i*40+20, DWORD_Buffer);
        sectionHeader64[i].pointerToRelocations = readDWord(file, memoryOffset+i*40+24, DWORD_Buffer);
        sectionHeader64[i].pointerToLineNumbers = readDWord(file, memoryOffset+i*40+28, DWORD_Buffer);
        sectionHeader64[i].numberOfRelocations = readWord(file, memoryOffset+i*40+32, WORD_Buffer);
        sectionHeader64[i].numberOfLineNumbers = readWord(file, memoryOffset+i*40+34, WORD_Buffer);
        sectionHeader64[i].characteristics = readDWord(file, memoryOffset+i*40+36, DWORD_Buffer);
    }
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void consoleOutput32(struct _IMAGE_DOS_HEADER dosHeader, struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, struct _SECTION_HEADER sectionHeader32[], FILE* file){
    printf("\nMS-DOS Header\n-------------\n"
    "dosHeader.e_magic: 0x%02x\n"
    "dosHeader.e_cblp: 0x%02x\n"
    "dosHeader.e_cp: 0x%02x\n"
    "dosHeader.e_crlc: 0x%02x\n"
    "dosHeader.e_cparhdr: 0x%02x\n"
    "dosHeader.e_minalloc: 0x%02x\n"
    "dosHeader.e_maxalloc: 0x%02x\n"
    "dosHeader.e_ss: 0x%02x\n"
    "dosHeader.e_sp: 0x%02x\n"
    "dosHeader.e_csum: 0x%02x\n"
    "dosHeader.e_ip: 0x%02x\n"
    "dosHeader.e_cs: 0x%02x\n"
    "dosHeader.e_lfarlc: 0x%02x\n"
    "dosHeader.e_ovno: 0x%02x\n"
    "dosHeader.e_res: 0x%02x%02x%02x%02x\n"
    "dosHeader.e_oemid: 0x%02x\n"
    "dosHeader.e_res2: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
    "dosHeader.e_lfanew: 0x%4x\n\n\n\n"
    ,dosHeader.e_magic, dosHeader.e_cblp, dosHeader.e_cp, dosHeader.e_crlc
    ,dosHeader.e_cparhdr, dosHeader.e_minalloc, dosHeader.e_maxalloc, dosHeader.e_ss
    ,dosHeader.e_sp, dosHeader.e_csum, dosHeader.e_ip, dosHeader.e_cs
    ,dosHeader.e_lfarlc, dosHeader.e_ovno, dosHeader.e_res[0], dosHeader.e_res[1]
    ,dosHeader.e_res[2], dosHeader.e_res[3], dosHeader.e_oemid, dosHeader.e_res2[0]
    ,dosHeader.e_res2[1], dosHeader.e_res2[2], dosHeader.e_res2[3], dosHeader.e_res2[4]
    ,dosHeader.e_res2[5], dosHeader.e_res2[6], dosHeader.e_res2[7], dosHeader.e_res2[8]
    ,dosHeader.e_res2[9], dosHeader.e_lfanew
    );

    char* machineArchitecture = getMachineArchitecture(reverse_endianess_u_int16_t(coffHeader.machine));
    char** characteristicsList = getCharacteristics(reverse_endianess_u_int16_t(coffHeader.characteristics));
    printf("\n\n\n\nCOFF Header\n-----------\n"
    "coffHeader.machine: %s\n"
    "coffHeader.numberOfSections: 0x%02x\n"
    "coffHeader.timeDateStamp: 0x%04x\n"
    "coffHeader.pointerToSymbolTable: 0x%04x\n"
    "coffHeader.numberOfSymbols: 0x%04x\n"
    "coffHeader.sizeOfOptionalHeader: 0x%02x\n"
    ,machineArchitecture, reverse_endianess_u_int16_t(coffHeader.numberOfSections), reverse_endianess_u_int32_t(coffHeader.timeDateStamp)
    ,reverse_endianess_u_int16_t(coffHeader.pointerToSymbolTable), reverse_endianess_u_int32_t(coffHeader.numberOfSymbols), reverse_endianess_u_int16_t(coffHeader.sizeOfOptionalHeader)
    );
    printf("coffHeader.characteristics:\n");
    size_t k=0;
    while(characteristicsList[k] != NULL){
        printf("\t%s\n", characteristicsList[k++]);
    }

    char *dataDirectoryList[16] = {"Export Table", "Import Table", "Resource Table", "Exception Table", "Certificate Table", "Base Relocation Table", "Debug", "Architecture", "Global Ptr", "TLS Table", "Load Config Table", "Bound Import", "IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"};
    printf("\n\n\n\nOptional Header\n---------------\n"
    "optionalHeader32.magic: 0x%02x\n"
    "optionalHeader32.majorLinkerVersion: 0x%x\n"
    "optionalHeader32.minorLinkerVersion: 0x%x\n"
    "optionalHeader32.sizeOfCode: 0x%04x\n"
    "optionalHeader32.sizeOfInitializedData: 0x%04x\n"
    "optionalHeader32.sizeOfUninitializedData: 0x%04x\n"
    "optionalHeader32.addressOfEntryPoint: 0x%04x\n"
    "optionalHeader32.baseOfCode: 0x%04x\n"
    "optionalHeader32.baseOfData: 0x%04x\n"
    "optionalHeader32.imageBase: 0x%04x\n"
    "optionalHeader32.sectionAlignment: 0x%04x\n"
    "optionalHeader32.fileAlignment: 0x%04x\n"
    "optionalHeader32.majorOperatingSystemVersion: 0x%02x\n"
    "optionalHeader32.minorOperatingSystemVersion: 0x%02x\n"
    "optionalHeader32.majorImageVersion: 0x%02x\n"
    "optionalHeader32.minorImageVersion: 0x%02x\n"
    "optionalHeader32.majorSubsystemVersion: 0x%02x\n"
    "optionalHeader32.minorSubsystemVersion: 0x%02x\n"
    "optionalHeader32.win32VersionValue: 0x%04x\n"
    "optionalHeader32.sizeOfImage: 0x%04x\n"
    "optionalHeader32.sizeOfHeaders: 0x%04x\n"
    "optionalHeader32.checksum: 0x%04x\n"
    "optionalHeader32.subsystem: 0x%02x\n"
    "optionalHeader32.dllCharacteristics: 0x%04x\n"
    "optionalHeader32.sizeOfStackReserve: 0x%04x\n"
    "optionalHeader32.sizeOfStackCommit: 0x%04x\n"
    "optionalHeader32.sizeOfHeapReserve: 0x%04x\n"
    "optionalHeader32.sizeOfHeapCommit: 0x%04x\n"
    "optionalHeader32.loaderFlags: 0x%04x\n"
    "optionalHeader32.numberOfRvaAndSizes: 0x%04x\n"
    ,reverse_endianess_u_int16_t(optionalHeader32.magic), reverse_endianess_u_int8_t(optionalHeader32.majorLinkerVersion)
    ,reverse_endianess_u_int8_t(optionalHeader32.minorLinkerVersion), reverse_endianess_u_int32_t(optionalHeader32.sizeOfCode)
    ,reverse_endianess_u_int32_t(optionalHeader32.sizeOfInitializedData), reverse_endianess_u_int32_t(optionalHeader32.sizeOfUninitializedData)
    ,reverse_endianess_u_int32_t(optionalHeader32.addressOfEntryPoint), reverse_endianess_u_int32_t(optionalHeader32.baseOfCode)
    ,reverse_endianess_u_int32_t(optionalHeader32.baseOfData), reverse_endianess_u_int32_t(optionalHeader32.imageBase)
    ,reverse_endianess_u_int32_t(optionalHeader32.sectionAlignment), reverse_endianess_u_int32_t(optionalHeader32.fileAlignment)
    ,reverse_endianess_u_int16_t(optionalHeader32.majorOperatingSystemVersion), reverse_endianess_u_int16_t(optionalHeader32.minorOperatingSystemVersion)
    ,reverse_endianess_u_int16_t(optionalHeader32.majorImageVersion), reverse_endianess_u_int16_t(optionalHeader32.minorImageVersion)
    ,reverse_endianess_u_int16_t(optionalHeader32.majorSubsystemVersion), reverse_endianess_u_int16_t(optionalHeader32.minorSubsystemVersion)
    ,reverse_endianess_u_int32_t(optionalHeader32.win32VersionValue), reverse_endianess_u_int32_t(optionalHeader32.sizeOfImage)
    ,reverse_endianess_u_int32_t(optionalHeader32.sizeOfHeaders), reverse_endianess_u_int32_t(optionalHeader32.checksum)
    ,reverse_endianess_u_int16_t(optionalHeader32.subsystem), reverse_endianess_u_int16_t(optionalHeader32.dllCharacteristics)
    ,reverse_endianess_u_int32_t(optionalHeader32.sizeOfStackReserve), reverse_endianess_u_int32_t(optionalHeader32.sizeOfStackCommit)
    ,reverse_endianess_u_int32_t(optionalHeader32.sizeOfHeapReserve), reverse_endianess_u_int32_t(optionalHeader32.sizeOfHeapCommit)
    ,reverse_endianess_u_int32_t(optionalHeader32.loaderFlags), reverse_endianess_u_int32_t(optionalHeader32.numberOfRvaAndSizes)
    );
    printf("\n\tData Directories:\n\n");
    for(size_t i=0;i<16;i++){
        if((optionalHeader32.dataDirectory[i].virtualAddress != 0) && (optionalHeader32.dataDirectory[i].size != 0)){
            printf(
            "\tData Directory: %s\n"
            "\t\tVirtualAddress: 0x%02x\n"
            "\t\tSize: 0x%02x\n"

            ,dataDirectoryList[i]
            ,reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[i].virtualAddress)
            ,reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[i].size)
            );
        }
    }

    u_int32_t numberOfRvaAndSizes = (((optionalHeader32.numberOfRvaAndSizes&255)&15)*16777216) + (((optionalHeader32.numberOfRvaAndSizes&255)>>4)*268435456) + ((((optionalHeader32.numberOfRvaAndSizes>>8)&255)&15)*65536) + ((((optionalHeader32.numberOfRvaAndSizes>>8)&255)>>4)*1048576) + (((optionalHeader32.numberOfRvaAndSizes>>16)&15)*256) + ((((optionalHeader32.numberOfRvaAndSizes>>16)&255)>>4)*4096) + (((optionalHeader32.numberOfRvaAndSizes>>24)&15)*1) + (((optionalHeader32.numberOfRvaAndSizes>>24)>>4)*16);
    printf("\n\n\n\nSection Headers\n---------------\n");
    for(size_t i=0;i<numberOfRvaAndSizes;i++){
        if(sectionHeader32[i].name != 0){
            char sectionNameBuf[4096];
            char* sectionNameString = convert_u_int64_t_ToString(sectionHeader32[i].name, sectionNameBuf);
            printf("sectionHeader.name: %s\n"
            "\tsectionHeader.virtualSize: 0x%04x\n"
            "\tsectionHeader.virtualAddress: 0x%04x\n"
            "\tsectionHeader.sizeOfRawData: 0x%04x\n"
            "\tsectionHeader.pointerToRawData: 0x%04x\n"
            "\tsectionHeader.pointerToRelocations: 0x%04x\n"
            "\tsectionHeader.pointerToLineNumbers: 0x%04x\n"
            "\tsectionHeader.numberOfRelocations: 0x%02x\n"
            "\tsectionHeader.numberOfLineNumbers: 0x%02x\n"
            "\tsectionHeader.characteristics: 0x%04x\n\n"
            ,sectionNameString, sectionHeader32[i].virtualSize, sectionHeader32[i].virtualAddress, sectionHeader32[i].sizeOfRawData
            ,sectionHeader32[i].pointerToRawData, sectionHeader32[i].pointerToRelocations, sectionHeader32[i].pointerToLineNumbers
            ,sectionHeader32[i].numberOfRelocations, sectionHeader32[i].numberOfLineNumbers, sectionHeader32[i].characteristics);
        }
    }

    u_int16_t numberOfSections = convert_WORD_To_u_int16_t(coffHeader.numberOfSections);
    bool consoleOutput = true;

    if(optionalHeader32.dataDirectory[0].virtualAddress != 0){
        printf("[Exports]\n--------------------\n");
        parseExportDirectory32(file, optionalHeader32, numberOfSections, sectionHeader32, consoleOutput);
    }

    if(optionalHeader32.dataDirectory[1].virtualAddress != 0){
        printf("[Imports]\n--------------------\n");
        parseImportDirectory32(file, optionalHeader32, numberOfSections, sectionHeader32, consoleOutput);
    }

    if(optionalHeader32.dataDirectory[2].virtualAddress != 0){
        printf("[Resources]\n--------------------\n");
        parseResourceDirectory32(file, optionalHeader32, numberOfSections, sectionHeader32, coffHeader, dosHeader, consoleOutput); 
    }

    if(optionalHeader32.dataDirectory[3].virtualAddress != 0){
        printf("\n\n[Base Relocations]\n--------------------\n");
        parseBaseRelocations32(file, optionalHeader32, numberOfSections, sectionHeader32, coffHeader, dosHeader, consoleOutput);
    }
    
    if(optionalHeader32.dataDirectory[6].virtualAddress != 0){
        printf("\n\n[Debug Information]\n\n");
        parseDebugDirectory32(file, optionalHeader32, numberOfSections, sectionHeader32, consoleOutput);
    }

    if(optionalHeader32.dataDirectory[10].virtualAddress != 0){
        printf("\n\n[Load Configuration]\n\n");
        parseLoadConfig32(file, optionalHeader32, numberOfSections, sectionHeader32, coffHeader, dosHeader, consoleOutput);
    }
}

void consoleOutput64(struct _IMAGE_DOS_HEADER dosHeader, struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, struct _SECTION_HEADER sectionHeader64[], FILE* file){
    printf("\nMS-DOS Header\n-------------\n"
    "dosHeader.e_magic: 0x%02x\n"
    "dosHeader.e_cblp: 0x%02x\n"
    "dosHeader.e_cp: 0x%02x\n"
    "dosHeader.e_crlc: 0x%02x\n"
    "dosHeader.e_cparhdr: 0x%02x\n"
    "dosHeader.e_minalloc: 0x%02x\n"
    "dosHeader.e_maxalloc: 0x%02x\n"
    "dosHeader.e_ss: 0x%02x\n"
    "dosHeader.e_sp: 0x%02x\n"
    "dosHeader.e_csum: 0x%02x\n"
    "dosHeader.e_ip: 0x%02x\n"
    "dosHeader.e_cs: 0x%02x\n"
    "dosHeader.e_lfarlc: 0x%02x\n"
    "dosHeader.e_ovno: 0x%02x\n"
    "dosHeader.e_res: 0x%02x%02x%02x%02x\n"
    "dosHeader.e_oemid: 0x%02x\n"
    "dosHeader.e_res2: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
    "dosHeader.e_lfanew: 0x%4x\n\n\n\n"
    ,dosHeader.e_magic, dosHeader.e_cblp, dosHeader.e_cp, dosHeader.e_crlc
    ,dosHeader.e_cparhdr, dosHeader.e_minalloc, dosHeader.e_maxalloc, dosHeader.e_ss
    ,dosHeader.e_sp, dosHeader.e_csum, dosHeader.e_ip, dosHeader.e_cs
    ,dosHeader.e_lfarlc, dosHeader.e_ovno, dosHeader.e_res[0], dosHeader.e_res[1]
    ,dosHeader.e_res[2], dosHeader.e_res[3], dosHeader.e_oemid, dosHeader.e_res2[0]
    ,dosHeader.e_res2[1], dosHeader.e_res2[2], dosHeader.e_res2[3], dosHeader.e_res2[4]
    ,dosHeader.e_res2[5], dosHeader.e_res2[6], dosHeader.e_res2[7], dosHeader.e_res2[8]
    ,dosHeader.e_res2[9], dosHeader.e_lfanew
    );

    char* machineArchitecture = getMachineArchitecture(reverse_endianess_u_int16_t(coffHeader.machine));
    char** characteristicsList = getCharacteristics(reverse_endianess_u_int16_t(coffHeader.characteristics));
    printf("\n\n\n\nCOFF Header\n-----------\n"
    "coffHeader.machine: %s\n"
    "coffHeader.numberOfSections: 0x%02x\n"
    "coffHeader.timeDateStamp: 0x%04x\n"
    "coffHeader.pointerToSymbolTable: 0x%04x\n"
    "coffHeader.numberOfSymbols: 0x%04x\n"
    "coffHeader.sizeOfOptionalHeader: 0x%02x\n"
    ,machineArchitecture, reverse_endianess_u_int16_t(coffHeader.numberOfSections), reverse_endianess_u_int32_t(coffHeader.timeDateStamp)
    ,reverse_endianess_u_int32_t(coffHeader.pointerToSymbolTable), reverse_endianess_u_int32_t(coffHeader.numberOfSymbols), reverse_endianess_u_int32_t(coffHeader.sizeOfOptionalHeader)
    );
    printf("coffHeader.characteristics:\n");
    size_t k=0;
    while(characteristicsList[k] != NULL){
        printf("\t%s\n", characteristicsList[k++]);
    }

    char *dataDirectoryList[16] = {"Export Table", "Import Table", "Resource Table", "Exception Table", "Certificate Table", "Base Relocation Table", "Debug", "Architecture", "Global Ptr", "TLS Table", "Load Config Table", "Bound Import", "IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"};
    printf("\n\n\n\nOptional Header\n---------------\n"
    "optionalHeader64.magic: 0x%02x\n"
    "optionalHeader64.majorLinkerVersion: 0x%x\n"
    "optionalHeader64.minorLinkerVersion: 0x%x\n"
    "optionalHeader64.sizeOfCode: 0x%04x\n"
    "optionalHeader64.sizeOfInitializedData: 0x%04x\n"
    "optionalHeader64.sizeOfUninitializedData: 0x%04x\n"
    "optionalHeader64.addressOfEntryPoint: 0x%04x\n"
    "optionalHeader64.baseOfCode: 0x%04x\n"
    "optionalHeader64.imageBase: 0x%04llx\n"
    "optionalHeader64.sectionAlignment: 0x%04x\n"
    "optionalHeader64.fileAlignment: 0x%04x\n"
    "optionalHeader64.majorOperatingSystemVersion: 0x%02x\n"
    "optionalHeader64.minorOperatingSystemVersion: 0x%02x\n"
    "optionalHeader64.majorImageVersion: 0x%02x\n"
    "optionalHeader64.minorImageVersion: 0x%02x\n"
    "optionalHeader64.majorSubsystemVersion: 0x%02x\n"
    "optionalHeader64.minorSubsystemVersion: 0x%02x\n"
    "optionalHeader64.win32VersionValue: 0x%04x\n"
    "optionalHeader64.sizeOfImage: 0x%04x\n"
    "optionalHeader64.sizeOfHeaders: 0x%04x\n"
    "optionalHeader64.checksum: 0x%04x\n"
    "optionalHeader64.subsystem: 0x%04x\n"
    "optionalHeader64.dllCharacteristics: 0x%04x\n"
    "optionalHeader64.sizeOfStackReserve: 0x%04llx\n"
    "optionalHeader64.sizeOfStackCommit: 0x%04llx\n"
    "optionalHeader64.sizeOfHeapReserve: 0x%04llx\n"
    "optionalHeader64.sizeOfHeapCommit: 0x%04llx\n"
    "optionalHeader64.loaderFlags: 0x%04x\n"
    "optionalHeader64.numberOfRvaAndSizes: 0x%04x\n"
    ,reverse_endianess_u_int16_t(optionalHeader64.magic),reverse_endianess_u_int8_t(optionalHeader64.majorLinkerVersion)
    ,reverse_endianess_u_int8_t(optionalHeader64.minorLinkerVersion), reverse_endianess_u_int32_t(optionalHeader64.sizeOfCode)
    ,reverse_endianess_u_int32_t(optionalHeader64.sizeOfInitializedData),reverse_endianess_u_int32_t(optionalHeader64.sizeOfUninitializedData)
    ,reverse_endianess_u_int32_t(optionalHeader64.addressOfEntryPoint), reverse_endianess_u_int32_t(optionalHeader64.baseOfCode)
    ,reverse_endianess_u_int64_t(optionalHeader64.imageBase), reverse_endianess_u_int32_t(optionalHeader64.sectionAlignment)
    ,reverse_endianess_u_int32_t(optionalHeader64.fileAlignment), reverse_endianess_u_int16_t(optionalHeader64.majorOperatingSystemVersion)
    ,reverse_endianess_u_int16_t(optionalHeader64.minorOperatingSystemVersion), reverse_endianess_u_int16_t(optionalHeader64.majorImageVersion)
    ,reverse_endianess_u_int16_t(optionalHeader64.minorImageVersion), reverse_endianess_u_int16_t(optionalHeader64.majorSubsystemVersion)
    ,reverse_endianess_u_int16_t(optionalHeader64.minorSubsystemVersion), reverse_endianess_u_int32_t(optionalHeader64.win32VersionValue)
    ,reverse_endianess_u_int32_t(optionalHeader64.sizeOfImage), reverse_endianess_u_int32_t(optionalHeader64.sizeOfHeaders)
    ,reverse_endianess_u_int32_t(optionalHeader64.checksum), reverse_endianess_u_int16_t(optionalHeader64.subsystem)
    ,reverse_endianess_u_int16_t(optionalHeader64.dllCharacteristics), reverse_endianess_u_int64_t(optionalHeader64.sizeOfStackReserve)
    ,reverse_endianess_u_int64_t(optionalHeader64.sizeOfStackCommit), reverse_endianess_u_int64_t(optionalHeader64.sizeOfHeapReserve)
    ,reverse_endianess_u_int64_t(optionalHeader64.sizeOfHeapCommit), reverse_endianess_u_int32_t(optionalHeader64.loaderFlags)
    ,reverse_endianess_u_int32_t(optionalHeader64.numberOfRvaAndSizes));
    printf("\n\tData Directories:\n\t-------------\n");
    for(size_t i=0;i<16;i++){
        if((optionalHeader64.dataDirectory[i].virtualAddress != 0) && (optionalHeader64.dataDirectory[i].size != 0)){
            printf(
            "\t%s\n"
            "\t\tVirtualAddress: 0x%02x\n"
            "\t\tSize: 0x%02x\n\n"
            ,dataDirectoryList[i]
            ,reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[i].virtualAddress)
            ,reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[i].size));
        }
        
    }

    u_int32_t numberOfRvaAndSizes = (((optionalHeader64.numberOfRvaAndSizes&255)&15)*16777216) + (((optionalHeader64.numberOfRvaAndSizes&255)>>4)*268435456) + ((((optionalHeader64.numberOfRvaAndSizes>>8)&255)&15)*65536) + ((((optionalHeader64.numberOfRvaAndSizes>>8)&255)>>4)*1048576) + (((optionalHeader64.numberOfRvaAndSizes>>16)&15)*256) + ((((optionalHeader64.numberOfRvaAndSizes>>16)&255)>>4)*4096) + (((optionalHeader64.numberOfRvaAndSizes>>24)&15)*1) + (((optionalHeader64.numberOfRvaAndSizes>>24)>>4)*16);
    
    printf("\n\n\n\nSection Headers\n---------------\n");
    for(size_t i=0;i<numberOfRvaAndSizes;i++){
        if(sectionHeader64[i].name != 0){
            char sectionNameBuf[4096];
            char* sectionNameString = convert_u_int64_t_ToString(sectionHeader64[i].name, sectionNameBuf);
            printf("sectionHeaders.name: %s\n"
            "\tsectionHeader.virtualSize: 0x%04x\n"
            "\tsectionHeader.virtualAddress: 0x%04x\n"
            "\tsectionHeader.sizeOfRawData: 0x%04x\n"
            "\tsectionHeader.pointerToRawData: 0x%04x\n"
            "\tsectionHeader.pointerToRelocations: 0x%04x\n"
            "\tsectionHeader.pointerToLineNumbers: 0x%04x\n"
            "\tsectionHeader.numberOfRelocations: 0x%02x\n"
            "\tsectionHeader.numberOfLineNumbers: 0x%02x\n"
            "\tsectionHeader.characteristics: 0x%04x\n\n"
            ,sectionNameString, sectionHeader64[i].virtualSize, sectionHeader64[i].virtualAddress, sectionHeader64[i].sizeOfRawData
            ,sectionHeader64[i].pointerToRawData, sectionHeader64[i].pointerToRelocations, sectionHeader64[i].pointerToLineNumbers
            ,sectionHeader64[i].numberOfRelocations, sectionHeader64[i].numberOfLineNumbers, sectionHeader64[i].characteristics);
        }
    }

    u_int16_t numberOfSections = convert_WORD_To_u_int16_t(coffHeader.numberOfSections);
    bool consoleOutput = true;

    if(optionalHeader64.dataDirectory[0].virtualAddress != 0){
        printf("[Exports]\n--------------------\n");
        parseExportDirectory64(file, optionalHeader64, numberOfSections, sectionHeader64, consoleOutput);
    }

    if(optionalHeader64.dataDirectory[1].virtualAddress != 0){
        printf("[Imports]\n--------------------\n");
        parseImportDirectory64(file, optionalHeader64, numberOfSections, sectionHeader64, consoleOutput);
    }

    if(optionalHeader64.dataDirectory[2].virtualAddress != 0){
        printf("[Resources]\n--------------------\n");
        parseResourceDirectory64(file, optionalHeader64, numberOfSections, sectionHeader64, coffHeader, dosHeader, consoleOutput); 
    }

    if(optionalHeader64.dataDirectory[3].virtualAddress != 0){
        printf("\n\n[Base Relocations]\n--------------------\n");
        parseBaseRelocations64(file, optionalHeader64, numberOfSections, sectionHeader64, coffHeader, dosHeader, consoleOutput);
    }
    
    if(optionalHeader64.dataDirectory[6].virtualAddress != 0){
        printf("\n[Debug Information]\n--------------------\n");
        parseDebugDirectory64(file, optionalHeader64, numberOfSections, sectionHeader64, consoleOutput);
    }

    if(optionalHeader64.dataDirectory[10].virtualAddress != 0){
        printf("\n\n[Load Configuration]\n--------------------\n");
        parseLoadConfig64(file, optionalHeader64, numberOfSections, sectionHeader64, coffHeader, dosHeader, consoleOutput);
    }
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

char* convert_u_int64_t_ToString(u_int64_t numericalValue, char computedString[4096]){
    char* st = computedString;
    char *src = st;
    char text[4096];
    char *dst = text;
    sprintf(computedString, "%04llx", numericalValue);
    while (*src != '\0')
    {
        const unsigned char high = hexdigit2int(*src++);
        const unsigned char low  = hexdigit2int(*src++);
        *dst++ = (high << 4) | low;
    }
    *dst = '\0';
    strcpy(computedString, text);
    return computedString;
}

u_int32_t convert_DWORD_To_u_int32_t(DWORD structureValue){
    u_int32_t convertedStructureValue = (((structureValue&255)&15)*16777216) + (((structureValue&255)>>4)*268435456) + ((((structureValue>>8)&255)&15)*65536) + ((((structureValue>>8)&255)>>4)*1048576) + (((structureValue>>16)&15)*256) + ((((structureValue>>16)&255)>>4)*4096) + (((structureValue>>24)&15)*1) + (((structureValue>>24)>>4)*16);
    return convertedStructureValue;
}

u_int16_t convert_WORD_To_u_int16_t(WORD structureValue){
    u_int16_t convertedStructureValue = (structureValue&15)*256 + ((structureValue>>4)&15)*4096 + (((structureValue>>8)&15)*1) + ((structureValue>>12)&15)*16;
    return convertedStructureValue;
}

u_int32_t convertRelativeAddressToDiskOffset(u_int32_t relativeAddress, u_int16_t numberOfSections,  struct _SECTION_HEADER sectionHeader[]){
    size_t i=0;

    for(i=0; i<numberOfSections; i++){
        u_int32_t sectionHeaderVirtualAddress = (((sectionHeader[i].virtualAddress&255)&15)*16777216) + (((sectionHeader[i].virtualAddress&255)>>4)*268435456) + ((((sectionHeader[i].virtualAddress>>8)&255)&15)*65536) + ((((sectionHeader[i].virtualAddress>>8)&255)>>4)*1048576) + (((sectionHeader[i].virtualAddress>>16)&15)*256) + ((((sectionHeader[i].virtualAddress>>16)&255)>>4)*4096) + (((sectionHeader[i].virtualAddress>>24)&15)*1) + (((sectionHeader[i].virtualAddress>>24)>>4)*16);
        u_int32_t sectionHeaderPointerToRawData = (((sectionHeader[i].pointerToRawData&255)&15)*16777216) + (((sectionHeader[i].pointerToRawData&255)>>4)*268435456) + ((((sectionHeader[i].pointerToRawData>>8)&255)&15)*65536) + ((((sectionHeader[i].pointerToRawData>>8)&255)>>4)*1048576) + (((sectionHeader[i].pointerToRawData>>16)&15)*256) + ((((sectionHeader[i].pointerToRawData>>16)&255)>>4)*4096) + (((sectionHeader[i].pointerToRawData>>24)&15)*1) + (((sectionHeader[i].pointerToRawData>>24)>>4)*16);
        u_int32_t sectionHeaderSizeOfRawData = (((sectionHeader[i].sizeOfRawData&255)&15)*16777216) + (((sectionHeader[i].sizeOfRawData&255)>>4)*268435456) + ((((sectionHeader[i].sizeOfRawData>>8)&255)&15)*65536) + ((((sectionHeader[i].sizeOfRawData>>8)&255)>>4)*1048576) + (((sectionHeader[i].sizeOfRawData>>16)&15)*256) + ((((sectionHeader[i].sizeOfRawData>>16)&255)>>4)*4096) + (((sectionHeader[i].sizeOfRawData>>24)&15)*1) + (((sectionHeader[i].sizeOfRawData>>24)>>4)*16);
        
        if((relativeAddress >= sectionHeaderVirtualAddress) && (relativeAddress <= (sectionHeaderVirtualAddress + sectionHeaderSizeOfRawData))){
            return (sectionHeaderPointerToRawData + relativeAddress - sectionHeaderVirtualAddress);
        }
    }

    return 0;
}

u_int64_t convertRelativeAddressToDiskOffset64(u_int64_t relativeAddress, u_int16_t numberOfSections,  struct _SECTION_HEADER sectionHeader[]){
    size_t i=0;

    for(i=0; i<numberOfSections; i++){
        u_int64_t sectionHeaderVirtualAddress = (((sectionHeader[i].virtualAddress&255)&15)*16777216) + (((sectionHeader[i].virtualAddress&255)>>4)*268435456) + ((((sectionHeader[i].virtualAddress>>8)&255)&15)*65536) + ((((sectionHeader[i].virtualAddress>>8)&255)>>4)*1048576) + (((sectionHeader[i].virtualAddress>>16)&15)*256) + ((((sectionHeader[i].virtualAddress>>16)&255)>>4)*4096) + (((sectionHeader[i].virtualAddress>>24)&15)*1) + (((sectionHeader[i].virtualAddress>>24)>>4)*16);
        u_int64_t sectionHeaderPointerToRawData = (((sectionHeader[i].pointerToRawData&255)&15)*16777216) + (((sectionHeader[i].pointerToRawData&255)>>4)*268435456) + ((((sectionHeader[i].pointerToRawData>>8)&255)&15)*65536) + ((((sectionHeader[i].pointerToRawData>>8)&255)>>4)*1048576) + (((sectionHeader[i].pointerToRawData>>16)&15)*256) + ((((sectionHeader[i].pointerToRawData>>16)&255)>>4)*4096) + (((sectionHeader[i].pointerToRawData>>24)&15)*1) + (((sectionHeader[i].pointerToRawData>>24)>>4)*16);
        u_int64_t sectionHeaderSizeOfRawData = (((sectionHeader[i].sizeOfRawData&255)&15)*16777216) + (((sectionHeader[i].sizeOfRawData&255)>>4)*268435456) + ((((sectionHeader[i].sizeOfRawData>>8)&255)&15)*65536) + ((((sectionHeader[i].sizeOfRawData>>8)&255)>>4)*1048576) + (((sectionHeader[i].sizeOfRawData>>16)&15)*256) + ((((sectionHeader[i].sizeOfRawData>>16)&255)>>4)*4096) + (((sectionHeader[i].sizeOfRawData>>24)&15)*1) + (((sectionHeader[i].sizeOfRawData>>24)>>4)*16);
        
        if((relativeAddress >= sectionHeaderVirtualAddress) && (relativeAddress <= (sectionHeaderVirtualAddress + sectionHeaderSizeOfRawData))){
            return (sectionHeaderPointerToRawData + relativeAddress - sectionHeaderVirtualAddress);
        }
    }

    return 0;
}

void parseImportDirectory32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int32_t importDescriptorOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[1].virtualAddress), numberOfSections, sectionHeader);
    struct _IMAGE_IMPORT_DESCRIPTOR32* importDescriptorArray = malloc(sizeof(struct _IMAGE_IMPORT_DESCRIPTOR32*));
    
    if(consoleOutput){    
        bool readAllImportDescriptors = false;
        size_t i=0;

        while(!readAllImportDescriptors){
            
            importDescriptorArray[i].u.OriginalFirstThunk.u1.ordinal = readDWord(file, importDescriptorOffset+i*20, DWORD_Buffer);
            importDescriptorArray[i].timeDateStamp = readDWord(file, importDescriptorOffset+i*20+4, DWORD_Buffer);
            importDescriptorArray[i].forwarderChain = readDWord(file, importDescriptorOffset+i*20+8, DWORD_Buffer);
            importDescriptorArray[i].name = readDWord(file, importDescriptorOffset+i*20+12, DWORD_Buffer);
            importDescriptorArray[i].FirstThunk.u1.addressOfData = readDWord(file, importDescriptorOffset+i*20+16, DWORD_Buffer);

            if((importDescriptorArray[i].u.OriginalFirstThunk.u1.ordinal == 0) && (importDescriptorArray[i].timeDateStamp == 0) && (importDescriptorArray[i].forwarderChain == 0) && (importDescriptorArray[i].name == 0) && (importDescriptorArray[i].FirstThunk.u1.addressOfData == 0)){
                readAllImportDescriptors = true;
                break;
            }

            u_int32_t DllNameOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(importDescriptorArray[i].name), numberOfSections, sectionHeader);
            u_int8_t DllLetter = reverse_endianess_u_int8_t(readByte(file, DllNameOffset, BYTE_Buffer));
            printf("[");
            while(DllLetter != 0 && (importDescriptorArray[i].u.OriginalFirstThunk.u1.ordinal != 0)){
                printf("%c", DllLetter);
                DllNameOffset+=1;
                DllLetter = reverse_endianess_u_int8_t(readByte(file, DllNameOffset, BYTE_Buffer));
            }
            printf("]\n");

            struct _IMAGE_THUNK_DATA32* originalFirstThunkArray = malloc(sizeof(struct _IMAGE_THUNK_DATA32*));
            u_int32_t originalFirstThunkArrayOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(importDescriptorArray[i].u.OriginalFirstThunk.u1.ordinal), numberOfSections, sectionHeader);
            size_t j=0;
            originalFirstThunkArray[j].u1.ordinal = reverse_endianess_u_int32_t(readDWord(file, originalFirstThunkArrayOffset, DWORD_Buffer));
            while((originalFirstThunkArray[j].u1.ordinal != 0)){
                j++;
                originalFirstThunkArray = realloc(originalFirstThunkArray, (j+1)*sizeof(struct _IMAGE_THUNK_DATA32*));
                originalFirstThunkArrayOffset = originalFirstThunkArrayOffset+4;
                originalFirstThunkArray[j].u1.ordinal = reverse_endianess_u_int32_t(readDWord(file, originalFirstThunkArrayOffset, DWORD_Buffer));
            }

            printf("\n");

            size_t k=0;
            while((originalFirstThunkArray[k].u1.ordinal != 0)){
                if(originalFirstThunkArray[k].u1.ordinal <= 0x8000000){
                    u_int32_t functionNameOffset = convertRelativeAddressToDiskOffset(originalFirstThunkArray[k].u1.ordinal, numberOfSections, sectionHeader);
                    functionNameOffset += 2; //skip the hint
                    u_int8_t functionLetter = reverse_endianess_u_int8_t(readByte(file, functionNameOffset, BYTE_Buffer));

                    while(functionLetter != 0){
                        printf("%c", functionLetter);
                        functionNameOffset+=1;
                        functionLetter = reverse_endianess_u_int8_t(readByte(file, functionNameOffset, BYTE_Buffer));
                    }
                    printf("\n");
                }
                k++;
            }
            
            printf("\n");
            i++;
            importDescriptorArray = realloc(importDescriptorArray, (i+1)*sizeof(struct _IMAGE_IMPORT_DESCRIPTOR32*));
        }
    }
    free(BYTE_Buffer);
    free(DWORD_Buffer);
    free(importDescriptorArray);
}

void parseImportDirectory64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int64_t* QWORD_Buffer = calloc(8, sizeof(u_int8_t));
    u_int32_t importDescriptorOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[1].virtualAddress), numberOfSections, sectionHeader);
    
    if(consoleOutput){    
        bool readAllImportDescriptors = false;
        size_t i=0;

        struct _IMAGE_IMPORT_DESCRIPTOR64* importDescriptorArray = malloc(sizeof(struct _IMAGE_IMPORT_DESCRIPTOR64*));
        while(!readAllImportDescriptors){
            
            importDescriptorArray[i].u.OriginalFirstThunk.u1.ordinal = readDWord(file, importDescriptorOffset+i*20, DWORD_Buffer);
            importDescriptorArray[i].timeDateStamp = readDWord(file, importDescriptorOffset+i*20+4, DWORD_Buffer);
            importDescriptorArray[i].forwarderChain = readDWord(file, importDescriptorOffset+i*20+8, DWORD_Buffer);
            importDescriptorArray[i].name = readDWord(file, importDescriptorOffset+i*20+12, DWORD_Buffer);
            importDescriptorArray[i].FirstThunk.u1.addressOfData = readDWord(file, importDescriptorOffset+i*20+16, DWORD_Buffer);

            if((importDescriptorArray[i].u.OriginalFirstThunk.u1.ordinal == 0) && (importDescriptorArray[i].timeDateStamp == 0) && (importDescriptorArray[i].forwarderChain == 0) && (importDescriptorArray[i].name == 0) && (importDescriptorArray[i].FirstThunk.u1.addressOfData == 0)){
                readAllImportDescriptors = true;
                break;
            }

            u_int32_t DllNameOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(importDescriptorArray[i].name), numberOfSections, sectionHeader);
            u_int8_t DllLetter = reverse_endianess_u_int8_t(readByte(file, DllNameOffset, BYTE_Buffer));
            printf("[");
            while(DllLetter != 0 && (importDescriptorArray[i].u.OriginalFirstThunk.u1.ordinal != 0)){
                printf("%c", DllLetter);
                DllNameOffset+=1;
                DllLetter = reverse_endianess_u_int8_t(readByte(file, DllNameOffset, BYTE_Buffer));
            }
            printf("]\n");       

            struct _IMAGE_THUNK_DATA64* originalFirstThunkArray = malloc(sizeof(struct _IMAGE_THUNK_DATA64*));
            
            u_int32_t originalFirstThunkArrayOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(importDescriptorArray[i].u.OriginalFirstThunk.u1.ordinal), numberOfSections, sectionHeader);
            size_t originalFirstThunkArrayIndex=0;
            size_t numberOfFunctions=0;
            
            originalFirstThunkArray[originalFirstThunkArrayIndex].u1.ordinal = reverse_endianess_u_int64_t(readQWord(file, originalFirstThunkArrayOffset, QWORD_Buffer));
            while(originalFirstThunkArray[originalFirstThunkArrayIndex].u1.ordinal != 0){
                numberOfFunctions++;
                originalFirstThunkArrayIndex++;
                originalFirstThunkArray = realloc(originalFirstThunkArray, (originalFirstThunkArrayIndex+1)*sizeof(struct _IMAGE_THUNK_DATA64*));
                originalFirstThunkArrayOffset += sizeof(QWORD);
                originalFirstThunkArray[originalFirstThunkArrayIndex].u1.ordinal = reverse_endianess_u_int64_t(readQWord(file, originalFirstThunkArrayOffset, QWORD_Buffer));
            }

            size_t k=0;
            while(originalFirstThunkArray[k].u1.ordinal != 0){
                if(originalFirstThunkArray[k].u1.ordinal <= 0x8000000000000000){
                    u_int64_t functionNameOffset = convertRelativeAddressToDiskOffset64(originalFirstThunkArray[k].u1.ordinal, numberOfSections, sectionHeader);
                    functionNameOffset += 2; //skip the hint
                    u_int8_t functionLetter = reverse_endianess_u_int8_t(readByte(file, functionNameOffset, BYTE_Buffer));
                    printf("\t");
                    while(functionLetter != 0){
                        printf("%c", functionLetter);
                        functionNameOffset+=1;
                        functionLetter = reverse_endianess_u_int8_t(readByte(file, functionNameOffset, BYTE_Buffer));
                    }
                    printf("\n");
                }
                k++;
            }
            
            printf("\n");
            i++;
            importDescriptorArray = realloc(importDescriptorArray, (i+1)*sizeof(struct _IMAGE_IMPORT_DESCRIPTOR64*));
        }
    }
    free(BYTE_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
    
}

void parseBoundImportsDirectory32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[]){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int32_t boundImportDescriptorOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[11].virtualAddress), numberOfSections, sectionHeader);

    struct _IMAGE_BOUND_IMPORT_DESCRIPTOR* boundImportDescriptorArray = malloc(sizeof(struct _IMAGE_BOUND_IMPORT_DESCRIPTOR*));
    bool readAllBoundImportDescriptors = false;
    size_t i=0;

    while(!readAllBoundImportDescriptors){

        boundImportDescriptorArray[i].timestamp = readDWord(file, boundImportDescriptorOffset+i*8, DWORD_Buffer);
        boundImportDescriptorArray[i].offsetModuleName = readWord(file, boundImportDescriptorOffset+i*8+4, WORD_Buffer);
        boundImportDescriptorArray[i].numberOfModuleForwarderRefs = readWord(file, boundImportDescriptorOffset+i*8+6, WORD_Buffer);

        if((boundImportDescriptorArray[i].timestamp == 0) && (boundImportDescriptorArray[i].offsetModuleName == 0) && (boundImportDescriptorArray[i].numberOfModuleForwarderRefs == 0)){
            readAllBoundImportDescriptors = true;
            break;
        }

        u_int32_t realOffsetModuleName = (u_int32_t)boundImportDescriptorArray[i].offsetModuleName + boundImportDescriptorOffset;
        u_int32_t realOffsetModuleNameRVA = convertRelativeAddressToDiskOffset(realOffsetModuleName, numberOfSections, sectionHeader);
        u_int8_t functionLetter = reverse_endianess_u_int8_t(readByte(file, realOffsetModuleNameRVA, BYTE_Buffer));

        while(functionLetter != 0){
                printf("%c", functionLetter);
                realOffsetModuleNameRVA+=1;
                functionLetter = reverse_endianess_u_int8_t(readByte(file, realOffsetModuleNameRVA, BYTE_Buffer));
            }
            printf("\n");

        if(boundImportDescriptorArray[i].numberOfModuleForwarderRefs != 0){    
            struct _IMAGE_BOUND_FORWARDER_REF* boundForwarderRefArray = malloc(sizeof(struct _IMAGE_BOUND_FORWARDER_REF*));
            u_int16_t f=0;

            while(f < boundImportDescriptorArray[i].numberOfModuleForwarderRefs){

                boundForwarderRefArray[f].timestamp = readDWord(file, boundImportDescriptorOffset+f*8, DWORD_Buffer);
                boundForwarderRefArray[f].offsetModuleName = readWord(file, boundImportDescriptorOffset+f*8+4, WORD_Buffer);
                boundForwarderRefArray[f].reserved = readWord(file, boundImportDescriptorOffset+f*8+6, WORD_Buffer);

                u_int32_t realForwarderRefOffsetModuleName = (u_int32_t)boundImportDescriptorArray[i].offsetModuleName + boundImportDescriptorOffset;
                u_int32_t realForwarderRefOffsetModuleNameRVA = convertRelativeAddressToDiskOffset(realForwarderRefOffsetModuleName, numberOfSections, sectionHeader);
                u_int8_t forwarderRefFunctionLetter = reverse_endianess_u_int8_t(readByte(file, realForwarderRefOffsetModuleNameRVA, BYTE_Buffer));

                while(forwarderRefFunctionLetter != 0){
                    printf("%c", forwarderRefFunctionLetter);
                    realForwarderRefOffsetModuleNameRVA+=1;
                    forwarderRefFunctionLetter = reverse_endianess_u_int8_t(readByte(file, realForwarderRefOffsetModuleNameRVA, BYTE_Buffer));
                }
                    printf("\n");

                f++;
                boundForwarderRefArray = realloc(boundForwarderRefArray, (f+1)*sizeof(struct _IMAGE_BOUND_FORWARDER_REF*));
            }

        }

    }    

    printf("\n");
    i++;
    boundImportDescriptorArray = realloc(boundImportDescriptorArray, (i+1)*sizeof(struct _IMAGE_IMPORT_DESCRIPTOR*));
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseBoundImportsDirectory64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[]){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int32_t boundImportDescriptorOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[11].virtualAddress), numberOfSections, sectionHeader);

    struct _IMAGE_BOUND_IMPORT_DESCRIPTOR* boundImportDescriptorArray = malloc(sizeof(struct _IMAGE_BOUND_IMPORT_DESCRIPTOR*));
    bool readAllBoundImportDescriptors = false;
    size_t i=0;

    while(!readAllBoundImportDescriptors){

        boundImportDescriptorArray[i].timestamp = readDWord(file, boundImportDescriptorOffset+i*8, DWORD_Buffer);
        boundImportDescriptorArray[i].offsetModuleName = readWord(file, boundImportDescriptorOffset+i*8+4, WORD_Buffer);
        boundImportDescriptorArray[i].numberOfModuleForwarderRefs = readWord(file, boundImportDescriptorOffset+i*8+6, WORD_Buffer);

        if((boundImportDescriptorArray[i].timestamp == 0) && (boundImportDescriptorArray[i].offsetModuleName == 0) && (boundImportDescriptorArray[i].numberOfModuleForwarderRefs == 0)){
            readAllBoundImportDescriptors = true;
            break;
        }

        u_int32_t realOffsetModuleName = (u_int32_t)boundImportDescriptorArray[i].offsetModuleName + boundImportDescriptorOffset;
        u_int32_t realOffsetModuleNameRVA = convertRelativeAddressToDiskOffset(realOffsetModuleName, numberOfSections, sectionHeader);
        u_int8_t functionLetter = reverse_endianess_u_int8_t(readByte(file, realOffsetModuleNameRVA, BYTE_Buffer));

        while(functionLetter != 0){
                printf("%c", functionLetter);
                realOffsetModuleNameRVA+=1;
                functionLetter = reverse_endianess_u_int8_t(readByte(file, realOffsetModuleNameRVA, BYTE_Buffer));
            }
            printf("\n");

        if(boundImportDescriptorArray[i].numberOfModuleForwarderRefs != 0){    
            struct _IMAGE_BOUND_FORWARDER_REF* boundForwarderRefArray = malloc(sizeof(struct _IMAGE_BOUND_FORWARDER_REF*));
            u_int16_t f=0;

            while(f < boundImportDescriptorArray[i].numberOfModuleForwarderRefs){

                boundForwarderRefArray[f].timestamp = readDWord(file, boundImportDescriptorOffset+f*8, DWORD_Buffer);
                boundForwarderRefArray[f].offsetModuleName = readWord(file, boundImportDescriptorOffset+f*8+4, WORD_Buffer);
                boundForwarderRefArray[f].reserved = readWord(file, boundImportDescriptorOffset+f*8+6, WORD_Buffer);

                u_int32_t realForwarderRefOffsetModuleName = (u_int32_t)boundImportDescriptorArray[i].offsetModuleName + boundImportDescriptorOffset;
                u_int32_t realForwarderRefOffsetModuleNameRVA = convertRelativeAddressToDiskOffset(realForwarderRefOffsetModuleName, numberOfSections, sectionHeader);
                u_int8_t forwarderRefFunctionLetter = reverse_endianess_u_int8_t(readByte(file, realForwarderRefOffsetModuleNameRVA, BYTE_Buffer));

                while(forwarderRefFunctionLetter != 0){
                    printf("%c", forwarderRefFunctionLetter);
                    realForwarderRefOffsetModuleNameRVA+=1;
                    forwarderRefFunctionLetter = reverse_endianess_u_int8_t(readByte(file, realForwarderRefOffsetModuleNameRVA, BYTE_Buffer));
                }
                    printf("\n");

                f++;
                boundForwarderRefArray = realloc(boundForwarderRefArray, (f+1)*sizeof(struct _IMAGE_BOUND_FORWARDER_REF*));
            }
        }
    }

    printf("\n");
    i++;
    boundImportDescriptorArray = realloc(boundImportDescriptorArray, (i+1)*sizeof(struct _IMAGE_IMPORT_DESCRIPTOR*));
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseExportDirectory64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int32_t exportDirectoryTableOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[0].virtualAddress), numberOfSections, sectionHeader);
    u_int32_t exportDirectorySize = reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[0].size);
    u_int32_t exportDirectoryTableOffset2 = reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[0].virtualAddress);

    static struct _IMAGE_EXPORT_DIRECTORY exportDataDirectory;
    exportDataDirectory.characteristics = readDWord(file, exportDirectoryTableOffset, DWORD_Buffer);
    exportDataDirectory.timeDateStamp = readDWord(file, exportDirectoryTableOffset+4, DWORD_Buffer);
    exportDataDirectory.majorVersion = readWord(file, exportDirectoryTableOffset+8, WORD_Buffer);
    exportDataDirectory.minorVersion = readWord(file, exportDirectoryTableOffset+10, WORD_Buffer);
    exportDataDirectory.name = readDWord(file, exportDirectoryTableOffset+12, DWORD_Buffer);
    exportDataDirectory.base = readDWord(file, exportDirectoryTableOffset+16, DWORD_Buffer);
    exportDataDirectory.numberOfFunctions = readDWord(file, exportDirectoryTableOffset+20, DWORD_Buffer);
    exportDataDirectory.numberOfNames = readDWord(file, exportDirectoryTableOffset+24, DWORD_Buffer);
    exportDataDirectory.addressOfFunctions = readDWord(file, exportDirectoryTableOffset+28, DWORD_Buffer);
    exportDataDirectory.addressOfNames = readDWord(file, exportDirectoryTableOffset+32, DWORD_Buffer);
    exportDataDirectory.addressOfOrdinals = readDWord(file, exportDirectoryTableOffset+36, DWORD_Buffer);

    if(consoleOutput){
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
        "Address of Ordinals: 0x%04x\n"
        ,reverse_endianess_u_int32_t(exportDataDirectory.characteristics), reverse_endianess_u_int32_t(exportDataDirectory.timeDateStamp), reverse_endianess_u_int16_t(exportDataDirectory.majorVersion), reverse_endianess_u_int16_t(exportDataDirectory.minorVersion),
        reverse_endianess_u_int32_t(exportDataDirectory.name), reverse_endianess_u_int32_t(exportDataDirectory.base), reverse_endianess_u_int32_t(exportDataDirectory.numberOfFunctions), reverse_endianess_u_int32_t(exportDataDirectory.numberOfNames),
        reverse_endianess_u_int32_t(exportDataDirectory.addressOfFunctions), reverse_endianess_u_int32_t(exportDataDirectory.addressOfNames), reverse_endianess_u_int32_t(exportDataDirectory.addressOfOrdinals));

        u_int32_t addressOfNamesOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(exportDataDirectory.addressOfNames), numberOfSections, sectionHeader);
        u_int32_t nameRVAArray[reverse_endianess_u_int32_t(exportDataDirectory.numberOfNames)];

        for(size_t i=0; i<reverse_endianess_u_int32_t(exportDataDirectory.numberOfNames);i++){
            nameRVAArray[i] = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(readDWord(file, addressOfNamesOffset+i*4, DWORD_Buffer)), numberOfSections, sectionHeader);
            u_int32_t exportedFunctionNameRVA = nameRVAArray[i];
            u_int8_t functionLetter = reverse_endianess_u_int8_t(readByte(file, exportedFunctionNameRVA, BYTE_Buffer));

            while(functionLetter != 0){
                    printf("%c", functionLetter);
                    exportedFunctionNameRVA+=1;
                    functionLetter = reverse_endianess_u_int8_t(readByte(file, exportedFunctionNameRVA, BYTE_Buffer));
                }
                printf("\n");
        }

        u_int32_t addressOfFunctionsOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(exportDataDirectory.addressOfFunctions), numberOfSections, sectionHeader);
        u_int32_t functionRVAArray[reverse_endianess_u_int32_t(exportDataDirectory.numberOfFunctions)];

        for(size_t i=0; i<reverse_endianess_u_int32_t(exportDataDirectory.numberOfFunctions);i++){
            functionRVAArray[i] = reverse_endianess_u_int32_t(readDWord(file, addressOfFunctionsOffset+i*4, DWORD_Buffer));
            
            if((exportDirectoryTableOffset2 < functionRVAArray[i]) && (functionRVAArray[i] < (exportDirectoryTableOffset2 + exportDirectorySize))){
                u_int32_t forwardedFunctionNameRVA = convertRelativeAddressToDiskOffset(functionRVAArray[i], numberOfSections, sectionHeader);
                u_int8_t functionLetter = reverse_endianess_u_int8_t(readByte(file, forwardedFunctionNameRVA, BYTE_Buffer));

                while(functionLetter != 0){
                    printf("%c", functionLetter);
                    forwardedFunctionNameRVA+=1;
                    functionLetter = reverse_endianess_u_int8_t(readByte(file, forwardedFunctionNameRVA, BYTE_Buffer));
                }
                printf("\n");
            }
        }
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseExportDirectory32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int32_t exportDirectoryTableOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[0].virtualAddress), numberOfSections, sectionHeader);
    u_int32_t exportDirectorySize = reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[0].size);
    u_int32_t exportDirectoryTableOffset2 = reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[0].virtualAddress);

    static struct _IMAGE_EXPORT_DIRECTORY exportDataDirectory;
    exportDataDirectory.characteristics = readDWord(file, exportDirectoryTableOffset, DWORD_Buffer);
    exportDataDirectory.timeDateStamp = readDWord(file, exportDirectoryTableOffset+4, DWORD_Buffer);
    exportDataDirectory.majorVersion = readWord(file, exportDirectoryTableOffset+8, WORD_Buffer);
    exportDataDirectory.minorVersion = readWord(file, exportDirectoryTableOffset+10, WORD_Buffer);
    exportDataDirectory.name = readDWord(file, exportDirectoryTableOffset+12, DWORD_Buffer);
    exportDataDirectory.base = readDWord(file, exportDirectoryTableOffset+16, DWORD_Buffer);
    exportDataDirectory.numberOfFunctions = readDWord(file, exportDirectoryTableOffset+20, DWORD_Buffer);
    exportDataDirectory.numberOfNames = readDWord(file, exportDirectoryTableOffset+24, DWORD_Buffer);
    exportDataDirectory.addressOfFunctions = readDWord(file, exportDirectoryTableOffset+28, DWORD_Buffer);
    exportDataDirectory.addressOfNames = readDWord(file, exportDirectoryTableOffset+32, DWORD_Buffer);
    exportDataDirectory.addressOfOrdinals = readDWord(file, exportDirectoryTableOffset+36, DWORD_Buffer);

    if(consoleOutput){
        printf("\n\n\n\nExport Directory\n---------------\n");
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
        "Address of Ordinals: 0x%04x\n"
        ,reverse_endianess_u_int32_t(exportDataDirectory.characteristics), reverse_endianess_u_int32_t(exportDataDirectory.timeDateStamp), reverse_endianess_u_int16_t(exportDataDirectory.majorVersion), reverse_endianess_u_int16_t(exportDataDirectory.minorVersion),
        reverse_endianess_u_int32_t(exportDataDirectory.name), reverse_endianess_u_int32_t(exportDataDirectory.base), reverse_endianess_u_int32_t(exportDataDirectory.numberOfFunctions), reverse_endianess_u_int32_t(exportDataDirectory.numberOfNames),
        reverse_endianess_u_int32_t(exportDataDirectory.addressOfFunctions), reverse_endianess_u_int32_t(exportDataDirectory.addressOfNames), reverse_endianess_u_int32_t(exportDataDirectory.addressOfOrdinals));

        u_int32_t addressOfNamesOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(exportDataDirectory.addressOfNames), numberOfSections, sectionHeader);
        u_int32_t nameRVAArray[reverse_endianess_u_int32_t(exportDataDirectory.numberOfNames)];

        for(size_t i=0; i<reverse_endianess_u_int32_t(exportDataDirectory.numberOfNames);i++){
            nameRVAArray[i] = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(readDWord(file, addressOfNamesOffset+i*4, DWORD_Buffer)), numberOfSections, sectionHeader);
            u_int32_t exportedFunctionNameRVA = nameRVAArray[i];
            u_int8_t functionLetter = reverse_endianess_u_int8_t(readByte(file, exportedFunctionNameRVA, BYTE_Buffer));

            while(functionLetter != 0){
                    printf("%c", functionLetter);
                    exportedFunctionNameRVA+=1;
                    functionLetter = reverse_endianess_u_int8_t(readByte(file, exportedFunctionNameRVA, BYTE_Buffer));
                }
                printf("\n");
        }

        u_int32_t addressOfFunctionsOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(exportDataDirectory.addressOfFunctions), numberOfSections, sectionHeader);
        u_int32_t functionRVAArray[reverse_endianess_u_int32_t(exportDataDirectory.numberOfFunctions)];

        for(size_t i=0; i<reverse_endianess_u_int32_t(exportDataDirectory.numberOfFunctions);i++){
            functionRVAArray[i] = reverse_endianess_u_int32_t(readDWord(file, addressOfFunctionsOffset+i*4, DWORD_Buffer));
            
            if((exportDirectoryTableOffset2 < functionRVAArray[i]) && (functionRVAArray[i] < (exportDirectoryTableOffset2 + exportDirectorySize))){
                u_int32_t forwardedFunctionNameRVA = convertRelativeAddressToDiskOffset(functionRVAArray[i], numberOfSections, sectionHeader);
                u_int8_t functionLetter = reverse_endianess_u_int8_t(readByte(file, forwardedFunctionNameRVA, BYTE_Buffer));

                while(functionLetter != 0){
                    printf("%c", functionLetter);
                    forwardedFunctionNameRVA+=1;
                    functionLetter = reverse_endianess_u_int8_t(readByte(file, forwardedFunctionNameRVA, BYTE_Buffer));
                }
                printf("\n");
            }
        }
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

char* getDebugType(u_int16_t machine){
    switch(machine){
        case 0x0:
            return "IMAGE_DEBUG_TYPE_UNKNOWN";
        case 0x01:
            return "IMAGE_DEBUG_TYPE_COFF";
        case 0x02:
            return "IMAGE_DEBUG_TYPE_CODEVIEW";
        case 0x03:
            return "IMAGE_DEBUG_TYPE_FPO";
        case 0x04:
            return "IMAGE_DEBUG_TYPE_MISC";
        case 0x05:
            return "IMAGE_DEBUG_TYPE_EXCEPTION";
        case 0x06:
            return "IMAGE_DEBUG_TYPE_FIXUP";
        case 0x07:
            return "IMAGE_DEBUG_TYPE_OMAP_TO_SRC";
        case 0x08:
            return "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC";
        case 0x09:
            return "IMAGE_DEBUG_TYPE_BORLAND";
        case 0x0A:
            return "IMAGE_DEBUG_TYPE_RESERVED10";
        case 0x0B:
            return "IMAGE_DEBUG_TYPE_CLSID";
        case 0x0C:
            return "IMAGE_DEBUG_TYPE_VC_FEATURE";
        case 0x0D:
            return "IMAGE_DEBUG_TYPE_POGO";
        case 0x0E:
            return "IMAGE_DEBUG_TYPE_ILTCG";
        case 0x0F:
            return "IMAGE_DEBUG_TYPE_MPX";
        case 0x10:
            return "IMAGE_DEBUG_TYPE_REPRO";
        default:
            return "UNDEFINED_DEBUG_TYPE";
    }
}

void parseDebugDirectory32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));

    size_t numberOfDebugDirectories = reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[6].size / sizeof(struct _IMAGE_DEBUG_DIRECTORY));
    struct _IMAGE_DEBUG_DIRECTORY* debugDirectoryArray = malloc(numberOfDebugDirectories * sizeof(struct _IMAGE_DEBUG_DIRECTORY));
    u_int32_t debugDirectoryStructureOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[6].virtualAddress), numberOfSections, sectionHeader);

    if(consoleOutput){
        for(size_t i=0;i<numberOfDebugDirectories;i++){
            debugDirectoryArray[i].characteristics = readDWord(file, debugDirectoryStructureOffset, DWORD_Buffer);
            debugDirectoryArray[i].timeDateStamp = readDWord(file, debugDirectoryStructureOffset+4, DWORD_Buffer);
            debugDirectoryArray[i].majorVersion = readWord(file, debugDirectoryStructureOffset+8, WORD_Buffer);
            debugDirectoryArray[i].minorVersion = readWord(file, debugDirectoryStructureOffset+10, WORD_Buffer);
            debugDirectoryArray[i].type = readDWord(file, debugDirectoryStructureOffset+12, DWORD_Buffer);
            debugDirectoryArray[i].sizeOfData = readDWord(file, debugDirectoryStructureOffset+16, DWORD_Buffer);
            debugDirectoryArray[i].addressOfRawData = readDWord(file, debugDirectoryStructureOffset+20, DWORD_Buffer);
            debugDirectoryArray[i].pointerToRawData = readDWord(file, debugDirectoryStructureOffset+24, DWORD_Buffer);

            printf(
                "debugDirectoryArray.characteristics: 0x%04x\n"
                "debugDirectoryArray.timeDateStamp: 0x%04x\n"
                "debugDirectoryArray.majorVersion: 0x%02x\n"
                "debugDirectoryArray.minorVersion: 0x%02x\n"
                "debugDirectoryArray.type: 0x%04x\n"
                "debugDirectoryArray.sizeOfData: 0x%04x\n"
                "debugDirectoryArray.addressOfRawData: 0x%04x\n"
                "debugDirectoryArray.pointerToRawData: 0x%04x\n"
                ,debugDirectoryArray[i].characteristics, debugDirectoryArray[i].timeDateStamp
                ,debugDirectoryArray[i].majorVersion, debugDirectoryArray[i].minorVersion
                ,debugDirectoryArray[i].type, debugDirectoryArray[i].sizeOfData
                ,debugDirectoryArray[i].addressOfRawData, debugDirectoryArray[i].pointerToRawData

            );


            u_int32_t cvSignatureOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(debugDirectoryArray[i].addressOfRawData), numberOfDebugDirectories, sectionHeader);
            u_int32_t cvSignature = readDWord(file, cvSignatureOffset, DWORD_Buffer);
            printf("PDB Path: \t");
            if(cvSignature == 0x3031424E){
                struct _CV_INFO_PDB20 pdb20;
                pdb20.header.Signature = readDWord(file, cvSignatureOffset, DWORD_Buffer);;
                pdb20.header.Offset = readDWord(file, cvSignatureOffset+4, DWORD_Buffer);
                pdb20.signature = readDWord(file, cvSignatureOffset+8, DWORD_Buffer);
                pdb20.age = readDWord(file, cvSignatureOffset+12, DWORD_Buffer);
                pdb20.pdbFileName = readByte(file, cvSignatureOffset+16, BYTE_Buffer);
                cvSignatureOffset += 20;
                while(pdb20.pdbFileName != 0){
                    printf("%c", pdb20.pdbFileName);
                    pdb20.pdbFileName = readByte(file, cvSignatureOffset++, BYTE_Buffer);
                }
                printf("\n\n");
            }

            if(cvSignature == 0x52534453){
                struct _CV_INFO_PDB70 pdb70;
                pdb70.cvSignature = readDWord(file, cvSignatureOffset, DWORD_Buffer);;
                pdb70.signature.Data1 = readDWord(file, cvSignatureOffset+4, DWORD_Buffer);
                pdb70.signature.Data2 = readWord(file, cvSignatureOffset+8, WORD_Buffer);
                pdb70.signature.Data3 = readWord(file, cvSignatureOffset+10, WORD_Buffer);
                for(size_t j=0;j<8;j++){
                    pdb70.signature.Data4[j] = readByte(file, cvSignatureOffset+12+j, BYTE_Buffer);
                }
                pdb70.age = readDWord(file, cvSignatureOffset+20, DWORD_Buffer);
                pdb70.pdbFileName = readByte(file, cvSignatureOffset+24, BYTE_Buffer);
                cvSignatureOffset += 25; //added extra byte so as to read the next letter of the stirng.
                while(pdb70.pdbFileName != 0){
                    printf("%c", pdb70.pdbFileName);
                    pdb70.pdbFileName = readByte(file, cvSignatureOffset++, BYTE_Buffer);
                }
                printf("\n\n");
            }

            debugDirectoryStructureOffset += 28;
        }
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseDebugDirectory64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));

    size_t numberOfDebugDirectories = reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[6].size / sizeof(struct _IMAGE_DEBUG_DIRECTORY));
    struct _IMAGE_DEBUG_DIRECTORY* debugDirectoryArray = malloc(numberOfDebugDirectories * sizeof(struct _IMAGE_DEBUG_DIRECTORY));
    u_int32_t debugDirectoryStructureOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[6].virtualAddress), numberOfSections, sectionHeader);

    if(consoleOutput){
        
        for(size_t i=0;i<numberOfDebugDirectories;i++){
            debugDirectoryArray[i].characteristics = readDWord(file, debugDirectoryStructureOffset, DWORD_Buffer);
            debugDirectoryArray[i].timeDateStamp = readDWord(file, debugDirectoryStructureOffset+4, DWORD_Buffer);
            debugDirectoryArray[i].majorVersion = readWord(file, debugDirectoryStructureOffset+8, WORD_Buffer);
            debugDirectoryArray[i].minorVersion = readWord(file, debugDirectoryStructureOffset+10, WORD_Buffer);
            debugDirectoryArray[i].type = readDWord(file, debugDirectoryStructureOffset+12, DWORD_Buffer);
            debugDirectoryArray[i].sizeOfData = readDWord(file, debugDirectoryStructureOffset+16, DWORD_Buffer);
            debugDirectoryArray[i].addressOfRawData = readDWord(file, debugDirectoryStructureOffset+20, DWORD_Buffer);
            debugDirectoryArray[i].pointerToRawData = readDWord(file, debugDirectoryStructureOffset+24, DWORD_Buffer);

            printf(
                "debugDirectoryArray.characteristics: 0x%04x\n"
                "debugDirectoryArray.timeDateStamp: 0x%04x\n"
                "debugDirectoryArray.majorVersion: 0x%02x\n"
                "debugDirectoryArray.minorVersion: 0x%02x\n"
                "debugDirectoryArray.type: 0x%04x\n"
                "debugDirectoryArray.sizeOfData: 0x%04x\n"
                "debugDirectoryArray.addressOfRawData: 0x%04x\n"
                "debugDirectoryArray.pointerToRawData: 0x%04x\n"
                ,debugDirectoryArray[i].characteristics, debugDirectoryArray[i].timeDateStamp
                ,debugDirectoryArray[i].majorVersion, debugDirectoryArray[i].minorVersion
                ,debugDirectoryArray[i].type, debugDirectoryArray[i].sizeOfData
                ,debugDirectoryArray[i].addressOfRawData, debugDirectoryArray[i].pointerToRawData

            );

            u_int32_t cvSignatureOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(debugDirectoryArray[i].addressOfRawData), numberOfSections, sectionHeader);
            u_int32_t cvSignature = readDWord(file, cvSignatureOffset, DWORD_Buffer);
            printf("PDB Path: \t");
            if(cvSignature == 0x3031424E){
                struct _CV_INFO_PDB20 pdb20;
                pdb20.header.Signature = readDWord(file, cvSignatureOffset, DWORD_Buffer);;
                pdb20.header.Offset = readDWord(file, cvSignatureOffset+4, DWORD_Buffer);
                pdb20.signature = readDWord(file, cvSignatureOffset+8, DWORD_Buffer);
                pdb20.age = readDWord(file, cvSignatureOffset+12, DWORD_Buffer);
                pdb20.pdbFileName = readByte(file, cvSignatureOffset+16, BYTE_Buffer);
                cvSignatureOffset += 20;
                while(pdb20.pdbFileName != 0){
                    printf("%c", pdb20.pdbFileName);
                    pdb20.pdbFileName = readByte(file, cvSignatureOffset++, BYTE_Buffer);
                }
                printf("\n\n");
            }

            if(cvSignature == 0x52534453){
                struct _CV_INFO_PDB70 pdb70;
                pdb70.cvSignature = readDWord(file, cvSignatureOffset, DWORD_Buffer);
                pdb70.signature.Data1 = readDWord(file, cvSignatureOffset+4, DWORD_Buffer);
                pdb70.signature.Data2 = readWord(file, cvSignatureOffset+8, WORD_Buffer);
                pdb70.signature.Data3 = readWord(file, cvSignatureOffset+10, WORD_Buffer);
                for(size_t j=0;j<8;j++){
                    pdb70.signature.Data4[j] = readByte(file, cvSignatureOffset+12+j, BYTE_Buffer);
                }
                pdb70.age = readDWord(file, cvSignatureOffset+20, DWORD_Buffer);
                pdb70.pdbFileName = readByte(file, cvSignatureOffset+24, BYTE_Buffer);
                cvSignatureOffset += 25; //added extra byte so as to read the next letter of the stirng.
                while(pdb70.pdbFileName != 0){
                    printf("%c", pdb70.pdbFileName);
                    pdb70.pdbFileName = readByte(file, cvSignatureOffset++, BYTE_Buffer);
                }
                printf("\n\n");
            }

            debugDirectoryStructureOffset += 28;
        }
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseRDirectory32(FILE* file, u_int32_t resourceDirectoryOffset, u_int32_t pointerToRawData, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[]){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    struct _IMAGE_RESOURCE_DIRECTORY directory;
    struct _IMAGE_RESOURCE_DIRECTORY_ENTRY directoryEntry;
    struct _IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA entryData;
    size_t entryCount = 0;

    directory.characteristics = readDWord(file, resourceDirectoryOffset, DWORD_Buffer);
    directory.timeDateStamp = readDWord(file, resourceDirectoryOffset+4, DWORD_Buffer);
    directory.majorVersion = readWord(file, resourceDirectoryOffset+8, WORD_Buffer);
    directory.minorVersion = readWord(file, resourceDirectoryOffset+10, WORD_Buffer);
    directory.numberOfNamedEntries = readWord(file, resourceDirectoryOffset+12, WORD_Buffer);
    directory.numberOfIdEntries = readWord(file, resourceDirectoryOffset+14, WORD_Buffer);

    entryCount = reverse_endianess_u_int16_t(directory.numberOfNamedEntries) + reverse_endianess_u_int16_t(directory.numberOfIdEntries);
    printf("IMAGE_RESOURCE_DIRECTORY:\n"
    "\tdirectoryRVA.characteristics: 0x%04x\n"
    "\tdirectoryRVA.timeDateStamp: 0x%04x\n"
    "\tdirectoryRVA.majorVersion: 0x%02x\n"
    "\tdirectoryRVA.minorVersion: 0x%02x\n"
    "\tdirectoryRVA.numberOfNamedEntries: 0x%02x\n"
    "\tdirectoryRVA.numberOfIdEntries: 0x%02x\n"
    ,directory.characteristics, directory.timeDateStamp, directory.majorVersion
    ,directory.minorVersion, directory.numberOfNamedEntries, directory.numberOfIdEntries
    );

    resourceDirectoryOffset += 16;
    size_t entryOffset = 0;    

    for(size_t i=0;i<entryCount;i++){
        directoryEntry.nameOffset = readDWord(file, resourceDirectoryOffset, DWORD_Buffer);
        directoryEntry.id = readDWord(file, resourceDirectoryOffset+4, DWORD_Buffer);

        if(reverse_endianess_u_int32_t(directoryEntry.id) >> 31){
            printf("IMAGE_RESOURCE_DIRECTORY_ENTRY (for Directory):\n"
                "\tdirectoryEntry.nameOffset: 0x%04x\n"
                "\tdirectoryEntry.id: 0x%04x\n"
                ,reverse_endianess_u_int32_t(directoryEntry.nameOffset), reverse_endianess_u_int32_t(directoryEntry.id)
            );

            if((reverse_endianess_u_int32_t(directoryEntry.nameOffset) >> 31)){
                u_int32_t nameRVA = (reverse_endianess_u_int32_t(directoryEntry.nameOffset) & 0x7FFFFFFF);
                u_int16_t nameCount = reverse_endianess_u_int16_t(readWord(file, nameRVA+pointerToRawData, WORD_Buffer));
                nameRVA += pointerToRawData + 1;
                while(nameCount){
                    printf("%c", (readWord(file, nameRVA, WORD_Buffer)));
                    nameRVA+=2;
                    nameCount--;
                }
                printf("\n");
            }
            else{
                u_int32_t id = (reverse_endianess_u_int32_t(directoryEntry.nameOffset) & 0x0000FFFF);
                printf("ID: %u\n", id);
            }

            u_int32_t offset = (reverse_endianess_u_int32_t(directoryEntry.id) & 0x7FFFFFFF);
            parseRDirectory32(file, offset + pointerToRawData, pointerToRawData, numberOfSections, sectionHeader);
        }
        else{
            printf("\tIMAGE_RESOURCE_DIRECTORY_ENTRY:\n"
                "\tdirectoryEntry.nameOffset: 0x%04x\n"
                "\tdirectoryEntry.id: 0x%04x\n"
                ,reverse_endianess_u_int32_t(directoryEntry.nameOffset), reverse_endianess_u_int32_t(directoryEntry.id)
            );
            if((reverse_endianess_u_int32_t(directoryEntry.nameOffset) >> 31)){
                u_int32_t nameRVA = (reverse_endianess_u_int32_t(directoryEntry.nameOffset) & 0x7FFFFFFF);
                u_int16_t nameCount = reverse_endianess_u_int16_t(readWord(file, nameRVA + pointerToRawData, WORD_Buffer));
                nameRVA = nameRVA + pointerToRawData + 1;
                while(nameCount){
                    printf("%c", (readWord(file, nameRVA, WORD_Buffer)));
                    nameRVA+=2;
                    nameCount--;
                }
                printf("\n");
            }
            else{
                u_int32_t id = (reverse_endianess_u_int32_t(directoryEntry.nameOffset) & 0x0000FFFF);
                printf("ID: %u\n", id);
            }
            
        }

        resourceDirectoryOffset += 8;
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    return;
}

void parseResourceDirectory32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int64_t* QWORD_Buffer = calloc(8, sizeof(u_int8_t));
    u_int32_t resourceSectionOffset = 0;
    bool foundResourceSection = false;

    u_int16_t sizeOfOptionalHeader = convert_WORD_To_u_int16_t(coffHeader.sizeOfOptionalHeader);
    u_int32_t memoryOffset = convert_DWORD_To_u_int32_t(dosHeader.e_lfanew) + 24 + sizeOfOptionalHeader;

    
    for(size_t i=0; i<numberOfSections; i++){
        char sectionNameBuf[4096];
        char* bufPointer = sectionNameBuf;
        char* resourceString = ".rsrc";
        sectionHeader[i].name = readQWord(file, memoryOffset+i*40, QWORD_Buffer);
        sectionHeader[i].pointerToRawData = readDWord(file, memoryOffset+i*40+20, DWORD_Buffer);
        char* sectionNameString = convert_u_int64_t_ToString(sectionHeader[i].name, sectionNameBuf);
        if(!strcmp(bufPointer, resourceString)){
            resourceSectionOffset = reverse_endianess_u_int32_t(sectionHeader[i].pointerToRawData);
            foundResourceSection = true;
            break;
        }
    }

    
    u_int32_t resourceDirectoryOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[2].virtualAddress), numberOfSections, sectionHeader);
    parseRDirectory32(file, resourceDirectoryOffset, resourceSectionOffset, numberOfSections, sectionHeader);

    
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void parseRDirectory64(FILE* file, u_int32_t resourceDirectoryOffset, u_int32_t pointerToRawData, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[]){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    struct _IMAGE_RESOURCE_DIRECTORY directory;
    struct _IMAGE_RESOURCE_DIRECTORY_ENTRY directoryEntry;
    struct _IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA entryData;
    size_t entryCount = 0;

    directory.characteristics = readDWord(file, resourceDirectoryOffset, DWORD_Buffer);
    directory.timeDateStamp = readDWord(file, resourceDirectoryOffset+4, DWORD_Buffer);
    directory.majorVersion = readWord(file, resourceDirectoryOffset+8, WORD_Buffer);
    directory.minorVersion = readWord(file, resourceDirectoryOffset+10, WORD_Buffer);
    directory.numberOfNamedEntries = readWord(file, resourceDirectoryOffset+12, WORD_Buffer);
    directory.numberOfIdEntries = readWord(file, resourceDirectoryOffset+14, WORD_Buffer);

    entryCount = reverse_endianess_u_int16_t(directory.numberOfNamedEntries) + reverse_endianess_u_int16_t(directory.numberOfIdEntries);
    printf("IMAGE_RESOURCE_DIRECTORY:\n"
    "\tdirectoryRVA.characteristics: 0x%04x\n"
    "\tdirectoryRVA.timeDateStamp: 0x%04x\n"
    "\tdirectoryRVA.majorVersion: 0x%02x\n"
    "\tdirectoryRVA.minorVersion: 0x%02x\n"
    "\tdirectoryRVA.numberOfNamedEntries: 0x%02x\n"
    "\tdirectoryRVA.numberOfIdEntries: 0x%02x\n"
    ,directory.characteristics, directory.timeDateStamp, directory.majorVersion
    ,directory.minorVersion, directory.numberOfNamedEntries, directory.numberOfIdEntries
    );

    resourceDirectoryOffset += 16;
    size_t entryOffset = 0;    

    for(size_t i=0;i<entryCount;i++){
        directoryEntry.nameOffset = readDWord(file, resourceDirectoryOffset, DWORD_Buffer);
        directoryEntry.id = readDWord(file, resourceDirectoryOffset+4, DWORD_Buffer);

        if(reverse_endianess_u_int32_t(directoryEntry.id) >> 31){
            printf("IMAGE_RESOURCE_DIRECTORY_ENTRY (for Directory):\n"
                "\tdirectoryEntry.nameOffset: 0x%04x\n"
                "\tdirectoryEntry.id: 0x%04x\n"
                ,reverse_endianess_u_int32_t(directoryEntry.nameOffset), reverse_endianess_u_int32_t(directoryEntry.id)
            );

            if((reverse_endianess_u_int32_t(directoryEntry.nameOffset) >> 31)){
                u_int32_t nameRVA = (reverse_endianess_u_int32_t(directoryEntry.nameOffset) & 0x7FFFFFFF);
                u_int16_t nameCount = reverse_endianess_u_int16_t(readWord(file, nameRVA+pointerToRawData, WORD_Buffer));
                nameRVA += pointerToRawData + 1;
                printf("[");
                while(nameCount){
                    printf("%c", (readWord(file, nameRVA, WORD_Buffer)));
                    nameRVA+=2;
                    nameCount--;
                }
                printf("]");
                printf("\n");
            }
            else{
                u_int32_t id = (reverse_endianess_u_int32_t(directoryEntry.nameOffset) & 0x0000FFFF);
                printf("ID: %u\n", id);
            }

            u_int32_t offset = (reverse_endianess_u_int32_t(directoryEntry.id) & 0x7FFFFFFF);
            parseRDirectory64(file, offset + pointerToRawData, pointerToRawData, numberOfSections, sectionHeader);
        }
        else{
            printf("\tIMAGE_RESOURCE_DIRECTORY_ENTRY:\n"
                "\tdirectoryEntry.nameOffset: 0x%04x\n"
                "\tdirectoryEntry.id: 0x%04x\n"
                ,reverse_endianess_u_int32_t(directoryEntry.nameOffset), reverse_endianess_u_int32_t(directoryEntry.id)
            );
            if((reverse_endianess_u_int32_t(directoryEntry.nameOffset) >> 31)){
                u_int32_t nameRVA = (reverse_endianess_u_int32_t(directoryEntry.nameOffset) & 0x7FFFFFFF);
                u_int16_t nameCount = reverse_endianess_u_int16_t(readWord(file, nameRVA + pointerToRawData, WORD_Buffer));
                nameRVA = nameRVA + pointerToRawData + 1;
                printf("[");
                while(nameCount){
                    printf("%c", (readWord(file, nameRVA, WORD_Buffer)));
                    nameRVA+=2;
                    nameCount--;
                }
                printf("]");
                printf("\n");
            }
            else{
                u_int32_t id = (reverse_endianess_u_int32_t(directoryEntry.nameOffset) & 0x0000FFFF);
                printf("ID: %u\n", id);
            }
            
        }

        resourceDirectoryOffset += 8;
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    return;
}

void parseResourceDirectory64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader64[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int64_t* QWORD_Buffer = calloc(8, sizeof(u_int8_t));
    u_int32_t resourceSectionOffset = 0;
    bool foundResourceSection = false;

    u_int16_t sizeOfOptionalHeader = convert_WORD_To_u_int16_t(coffHeader.sizeOfOptionalHeader);
    u_int32_t memoryOffset = convert_DWORD_To_u_int32_t(dosHeader.e_lfanew) + 24 + sizeOfOptionalHeader;

    
    for(size_t i=0; i<numberOfSections; i++){
        char sectionNameBuf[4096];
        char* bufPointer = sectionNameBuf;
        char* resourceString = ".rsrc";
        sectionHeader64[i].name = readQWord(file, memoryOffset+i*40, QWORD_Buffer);
        sectionHeader64[i].pointerToRawData = readDWord(file, memoryOffset+i*40+20, DWORD_Buffer);
        char* sectionNameString = convert_u_int64_t_ToString(sectionHeader64[i].name, sectionNameBuf);
        if(!strcmp(bufPointer, resourceString)){
            resourceSectionOffset = reverse_endianess_u_int32_t(sectionHeader64[i].pointerToRawData);
            foundResourceSection = true;
            break;
        }
    }

    
    u_int32_t resourceDirectoryOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[2].virtualAddress), numberOfSections, sectionHeader64);
    parseRDirectory64(file, resourceDirectoryOffset, resourceSectionOffset, numberOfSections, sectionHeader64);

    
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void parseBaseRelocations32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int32_t baseRelocationSectionOffset = 0;
    
    baseRelocationSectionOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[5].virtualAddress), numberOfSections, sectionHeader);
    struct _IMAGE_BASE_RELOCATION imageBaseReloc;
    imageBaseReloc.pageRVA = reverse_endianess_u_int32_t(readDWord(file, baseRelocationSectionOffset, DWORD_Buffer));
    imageBaseReloc.blockSize = reverse_endianess_u_int32_t(readDWord(file, baseRelocationSectionOffset+4, DWORD_Buffer));
    
    baseRelocationSectionOffset += 8;
    size_t typeCount = (imageBaseReloc.blockSize - 0x8) / 0x2;

    while((imageBaseReloc.pageRVA != 0) && (imageBaseReloc.blockSize != 0)){
        printf(
            "\n\npageRVA: 0x%04x\n"
            "blockSize: 0x%04x\n"
            ,imageBaseReloc.pageRVA, imageBaseReloc.blockSize
        );
        typeCount = (imageBaseReloc.blockSize - 0x8) / 0x2;
        printf("---------------------------\n");
        u_int16_t fourbitValue = 0;
        u_int16_t twelvebitValue = 0;

        while(typeCount--){
            fourbitValue = (reverse_endianess_u_int16_t(readWord(file, baseRelocationSectionOffset, WORD_Buffer)) >> 12);
            twelvebitValue = (reverse_endianess_u_int16_t(readWord(file, baseRelocationSectionOffset, WORD_Buffer)) & 0x0FFF);
            printf(
            "\ttype: 0x%02x\n"
            "\taddress: 0x%02x\n"
            ,(fourbitValue), (twelvebitValue)+imageBaseReloc.pageRVA
            );
            baseRelocationSectionOffset += 2;
        }

        imageBaseReloc.pageRVA = reverse_endianess_u_int32_t(readDWord(file, baseRelocationSectionOffset, DWORD_Buffer));
        imageBaseReloc.blockSize = reverse_endianess_u_int32_t(readDWord(file, baseRelocationSectionOffset+4, DWORD_Buffer));
        baseRelocationSectionOffset += 8;
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseBaseRelocations64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader64[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int64_t* QWORD_Buffer = calloc(8, sizeof(u_int8_t));
    u_int32_t baseRelocationSectionOffset = 0;
    
    baseRelocationSectionOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[5].virtualAddress), numberOfSections, sectionHeader64);
    struct _IMAGE_BASE_RELOCATION imageBaseReloc;
    imageBaseReloc.pageRVA = reverse_endianess_u_int32_t(readDWord(file, baseRelocationSectionOffset, DWORD_Buffer));
    imageBaseReloc.blockSize = reverse_endianess_u_int32_t(readDWord(file, baseRelocationSectionOffset+4, DWORD_Buffer));
    
    baseRelocationSectionOffset += 8;
    size_t typeCount = (imageBaseReloc.blockSize - 0x8) / 0x2;

    while((imageBaseReloc.pageRVA != 0) && (imageBaseReloc.blockSize != 0)){
        printf(
            "\n\npageRVA: 0x%04x\n"
            "blockSize: 0x%04x\n"
            ,imageBaseReloc.pageRVA, imageBaseReloc.blockSize
        );
        typeCount = (imageBaseReloc.blockSize - 0x8) / 0x2;
        printf("---------------------------\n");
        u_int16_t fourbitValue = 0;
        u_int16_t twelvebitValue = 0;

        while(typeCount--){
            fourbitValue = (reverse_endianess_u_int16_t(readWord(file, baseRelocationSectionOffset, WORD_Buffer)) >> 12);
            twelvebitValue = (reverse_endianess_u_int16_t(readWord(file, baseRelocationSectionOffset, WORD_Buffer)) & 0x0FFF);
            printf(
            "\ttype: 0x%02x\n"
            "\taddress: 0x%02x\n"
            ,(fourbitValue), (twelvebitValue)+imageBaseReloc.pageRVA
            );
            baseRelocationSectionOffset += 2;
        }

        imageBaseReloc.pageRVA = reverse_endianess_u_int32_t(readDWord(file, baseRelocationSectionOffset, DWORD_Buffer));
        imageBaseReloc.blockSize = reverse_endianess_u_int32_t(readDWord(file, baseRelocationSectionOffset+4, DWORD_Buffer));
        baseRelocationSectionOffset += 8;
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void parseTLSDirectory32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader32[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    struct _IMAGE_TLS_DIRECTORY32* imagetlsdirectory32 = malloc(sizeof(struct _IMAGE_TLS_DIRECTORY32*));
    size_t i=0;

    u_int32_t tlsOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[9].virtualAddress), numberOfSections, sectionHeader32);

    imagetlsdirectory32[0].startAddressOfRawData = readDWord(file, tlsOffset, DWORD_Buffer);
    imagetlsdirectory32[0].endAddressOfRawData = readDWord(file, tlsOffset+4, DWORD_Buffer);
    imagetlsdirectory32[0].addressOfIndex = readDWord(file, tlsOffset+8, DWORD_Buffer);
    imagetlsdirectory32[0].addressOfCallBacks = readDWord(file, tlsOffset+12, DWORD_Buffer);
    imagetlsdirectory32[0].sizeOfZeroFill = readDWord(file, tlsOffset+16, DWORD_Buffer);
    imagetlsdirectory32[0].characteristics = readDWord(file, tlsOffset+20, DWORD_Buffer);
    tlsOffset += 24;

    while((imagetlsdirectory32[i].startAddressOfRawData != 0) && (imagetlsdirectory32[i].endAddressOfRawData != 0) && (imagetlsdirectory32[i].addressOfIndex != 0) && (imagetlsdirectory32[i].addressOfCallBacks) && (imagetlsdirectory32[i].sizeOfZeroFill) && (imagetlsdirectory32[i].characteristics != 0)){
        printf(
            "startAddressOfRawData: 0x%04x\n"
            "endAddressOfRawData: 0x%04x\n"
            "addressOfIndex: 0x%04x\n"
            "addressOfCallBacks: 0x%04x\n"
            "sizeOfZeroFill: 0x%04x\n"
            "characteristics: 0x%04x\n"
            ,imagetlsdirectory32[i].startAddressOfRawData, imagetlsdirectory32[i].endAddressOfRawData
            ,imagetlsdirectory32[i].addressOfIndex, imagetlsdirectory32[i].addressOfCallBacks
            ,imagetlsdirectory32[i].sizeOfZeroFill, imagetlsdirectory32[i].characteristics
        );

        imagetlsdirectory32[i].startAddressOfRawData = readDWord(file, tlsOffset, DWORD_Buffer);
        imagetlsdirectory32[i].endAddressOfRawData = readDWord(file, tlsOffset+4, DWORD_Buffer);
        imagetlsdirectory32[i].addressOfIndex = readDWord(file, tlsOffset+8, DWORD_Buffer);
        imagetlsdirectory32[i].addressOfCallBacks = readDWord(file, tlsOffset+12, DWORD_Buffer);
        imagetlsdirectory32[i].sizeOfZeroFill = readDWord(file, tlsOffset+16, DWORD_Buffer);
        imagetlsdirectory32[i].characteristics = readDWord(file, tlsOffset+20, DWORD_Buffer);
        tlsOffset += 24;
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseTLSDirectory64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader64[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int64_t* QWORD_Buffer = calloc(8, sizeof(u_int8_t));
    struct _IMAGE_TLS_DIRECTORY64* imagetlsdirectory64 = malloc(sizeof(struct _IMAGE_TLS_DIRECTORY64*));
    size_t i=0;

    u_int32_t tlsOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[9].virtualAddress), numberOfSections, sectionHeader64);

    imagetlsdirectory64[0].startAddressOfRawData = readQWord(file, tlsOffset, QWORD_Buffer);
    imagetlsdirectory64[0].endAddressOfRawData = readQWord(file, tlsOffset+8, QWORD_Buffer);
    imagetlsdirectory64[0].addressOfIndex = readQWord(file, tlsOffset+16, QWORD_Buffer);
    imagetlsdirectory64[0].addressOfCallBacks = readQWord(file, tlsOffset+24, QWORD_Buffer);
    imagetlsdirectory64[0].sizeOfZeroFill = readDWord(file, tlsOffset+32, DWORD_Buffer);
    imagetlsdirectory64[0].characteristics = readDWord(file, tlsOffset+36, DWORD_Buffer);

    tlsOffset += 40;

    while((imagetlsdirectory64[i].startAddressOfRawData != 0) && (imagetlsdirectory64[i].endAddressOfRawData != 0) && (imagetlsdirectory64[i].addressOfIndex != 0) && (imagetlsdirectory64[i].addressOfCallBacks) && (imagetlsdirectory64[i].sizeOfZeroFill) && (imagetlsdirectory64[i].characteristics != 0)){
        printf(
            "startAddressOfRawData: 0x%04llx\n"
            "endAddressOfRawData: 0x%04llx\n"
            "addressOfIndex: 0x%04llx\n"
            "addressOfCallBacks: 0x%04llx\n"
            "sizeOfZeroFill: 0x%04x\n"
            "characteristics: 0x%04x\n"
            ,imagetlsdirectory64[i].startAddressOfRawData, imagetlsdirectory64[i].endAddressOfRawData
            ,imagetlsdirectory64[i].addressOfIndex, imagetlsdirectory64[i].addressOfCallBacks
            ,imagetlsdirectory64[i].sizeOfZeroFill, imagetlsdirectory64[i].characteristics
        );

        imagetlsdirectory64[i].startAddressOfRawData = readQWord(file, tlsOffset, QWORD_Buffer);
        imagetlsdirectory64[i].endAddressOfRawData = readQWord(file, tlsOffset+8, QWORD_Buffer);
        imagetlsdirectory64[i].addressOfIndex = readQWord(file, tlsOffset+16, QWORD_Buffer);
        imagetlsdirectory64[i].addressOfCallBacks = readQWord(file, tlsOffset+24, QWORD_Buffer);
        imagetlsdirectory64[i].sizeOfZeroFill = readDWord(file, tlsOffset+32, DWORD_Buffer);
        imagetlsdirectory64[i].characteristics = readDWord(file, tlsOffset+36, DWORD_Buffer);
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void parseLoadConfig32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int64_t* QWORD_Buffer = calloc(8, sizeof(u_int8_t));


    struct _IMAGE_LOAD_CONFIG32 imageLoadConfig32;
    u_int32_t loadConfigOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[10].virtualAddress), numberOfSections, sectionHeader);

    
    imageLoadConfig32.characteristics = readDWord(file, loadConfigOffset, DWORD_Buffer);
    imageLoadConfig32.timeDateStamp = readDWord(file, loadConfigOffset+4, DWORD_Buffer);
    imageLoadConfig32.majorVersion = readWord(file, loadConfigOffset+8, WORD_Buffer);
    imageLoadConfig32.minorVersion = readWord(file, loadConfigOffset+10, WORD_Buffer);
    imageLoadConfig32.globalFlagsClear = readDWord(file, loadConfigOffset+12, DWORD_Buffer);
    imageLoadConfig32.globalFlagsSet = readDWord(file, loadConfigOffset+16, DWORD_Buffer);
    imageLoadConfig32.criticalSectionDefaultTimeout = readDWord(file, loadConfigOffset+20, DWORD_Buffer);
    imageLoadConfig32.deCommitFreeBlockThreshold = readDWord(file, loadConfigOffset+24, DWORD_Buffer);
    imageLoadConfig32.deCommitTotalFreeThreshold = readDWord(file, loadConfigOffset+28, DWORD_Buffer);
    imageLoadConfig32.lockPrefixTable = readDWord(file, loadConfigOffset+32, DWORD_Buffer);
    imageLoadConfig32.maximumAllocationSize = readDWord(file, loadConfigOffset+36, DWORD_Buffer);
    imageLoadConfig32.virtualMemoryThreshold = readDWord(file, loadConfigOffset+40, DWORD_Buffer);
    imageLoadConfig32.processAffinityMask = readDWord(file, loadConfigOffset+44, DWORD_Buffer);
    imageLoadConfig32.processHeapFlags = readDWord(file, loadConfigOffset+48, DWORD_Buffer);
    imageLoadConfig32.cSDVersion = readWord(file, loadConfigOffset+52, WORD_Buffer);
    imageLoadConfig32.reserved = readWord(file, loadConfigOffset+54, WORD_Buffer);
    imageLoadConfig32.editList = readDWord(file, loadConfigOffset+56, DWORD_Buffer);
    imageLoadConfig32.securityCookie = readDWord(file, loadConfigOffset+60, DWORD_Buffer);
    imageLoadConfig32.sEHandlerTable = readDWord(file, loadConfigOffset+64, DWORD_Buffer);
    imageLoadConfig32.sEHandlerCount = readDWord(file, loadConfigOffset+68, DWORD_Buffer);
    imageLoadConfig32.guardCFCheckFunctionPointer = readDWord(file, loadConfigOffset+72, DWORD_Buffer);
    imageLoadConfig32.guardCFDispatchFunctionPointer = readDWord(file, loadConfigOffset+76, DWORD_Buffer);
    imageLoadConfig32.guardCFFunctionTable = readDWord(file, loadConfigOffset+80, DWORD_Buffer);
    imageLoadConfig32.guardCFFunctionCount = readDWord(file, loadConfigOffset+84, DWORD_Buffer);
    imageLoadConfig32.guardFlags = readDWord(file, loadConfigOffset+88, DWORD_Buffer);
    imageLoadConfig32.codeIntegrity[0] = readDWord(file, loadConfigOffset+92, DWORD_Buffer);
    imageLoadConfig32.codeIntegrity[1] = readDWord(file, loadConfigOffset+96, DWORD_Buffer);
    imageLoadConfig32.codeIntegrity[2] = readDWord(file, loadConfigOffset+100, DWORD_Buffer);
    imageLoadConfig32.guardAddressTakenIatEntryTable = readDWord(file, loadConfigOffset+104, DWORD_Buffer);
    imageLoadConfig32.guardAddressTakenIatEntryCount = readDWord(file, loadConfigOffset+108, DWORD_Buffer);
    imageLoadConfig32.guardLongJumpTargetTable = readDWord(file, loadConfigOffset+112, DWORD_Buffer);
    imageLoadConfig32.guardLongJumpTargetCount = readDWord(file, loadConfigOffset+116, DWORD_Buffer);
    
    if(consoleOutput){
        printf(
            "imageLoadConfig32.characteristics: 0x%04x\n"
            "imageLoadConfig32.timeDateStamp: 0x%04x\n"
            "imageLoadConfig32.majorVersion: 0x%04x\n"
            "imageLoadConfig32.minorVersion: 0x%04x\n"
            "imageLoadConfig32.globalFlagsClear: 0x%04x\n"
            "imageLoadConfig32.globalFlagsSet: 0x%04x\n"
            "imageLoadConfig32.criticalSectionDefaultTimeout: 0x%04x\n"
            "imageLoadConfig32.deCommitFreeBlockThreshold: 0x%04x\n"
            "imageLoadConfig32.deCommitTotalFreeThreshold: 0x%04x\n"
            "imageLoadConfig32.lockPrefixTable: 0x%04x\n"
            "imageLoadConfig32.maximumAllocationSize: 0x%04x\n"
            "imageLoadConfig32.virtualMemoryThreshold: 0x%04x\n"
            "imageLoadConfig32.processAffinityMask: 0x%04x\n"
            "imageLoadConfig32.processHeapFlags: 0x%04x\n"
            "imageLoadConfig32.cSDVersion: 0x%04x\n"
            "imageLoadConfig32.reserved: 0x%04x\n"
            "imageLoadConfig32.editList: 0x%04x\n"
            "imageLoadConfig32.securityCookie: 0x%04x\n"
            "imageLoadConfig32.sEHandlerTable: 0x%04x\n"
            "imageLoadConfig32.sEHandlerCount: 0x%04x\n"
            "imageLoadConfig32.guardCFCheckFunctionPointer: 0x%04x\n"
            "imageLoadConfig32.guardCFDispatchFunctionPointer: 0x%04x\n"
            "imageLoadConfig32.guardCFFunctionTable: 0x%04x\n"
            "imageLoadConfig32.guardCFFunctionCount: 0x%04x\n"
            "imageLoadConfig32.guardFlags: 0x%04x\n"
            "imageLoadConfig32.codeIntegrity[0]: 0x%04x\n"
            "imageLoadConfig32.codeIntegrity[1]: 0x%04x\n"
            "imageLoadConfig32.codeIntegrity[2]: 0x%04x\n"
            "imageLoadConfig32.guardAddressTakenIatEntryTable: 0x%04x\n"
            "imageLoadConfig32.guardAddressTakenIatEntryCount: 0x%04x\n"
            "imageLoadConfig32.guardLongJumpTargetTable: 0x%04x\n"
            "imageLoadConfig32.guardLongJumpTargetCount: 0x%04x\n"
            ,imageLoadConfig32.characteristics, imageLoadConfig32.timeDateStamp
            ,imageLoadConfig32.majorVersion, imageLoadConfig32.minorVersion
            ,imageLoadConfig32.globalFlagsClear, imageLoadConfig32.globalFlagsSet
            ,imageLoadConfig32.criticalSectionDefaultTimeout, imageLoadConfig32.deCommitFreeBlockThreshold
            ,imageLoadConfig32.deCommitTotalFreeThreshold
            ,imageLoadConfig32.lockPrefixTable, imageLoadConfig32.maximumAllocationSize
            ,imageLoadConfig32.virtualMemoryThreshold, imageLoadConfig32.processAffinityMask
            ,imageLoadConfig32.processHeapFlags, imageLoadConfig32.cSDVersion
            ,imageLoadConfig32.reserved, imageLoadConfig32.editList
            ,imageLoadConfig32.securityCookie, imageLoadConfig32.sEHandlerTable
            ,imageLoadConfig32.sEHandlerCount, imageLoadConfig32.guardCFCheckFunctionPointer
            ,imageLoadConfig32.guardCFDispatchFunctionPointer, imageLoadConfig32.guardCFFunctionTable
            ,imageLoadConfig32.guardCFFunctionCount, imageLoadConfig32.guardFlags
            ,imageLoadConfig32.codeIntegrity[0], imageLoadConfig32.codeIntegrity[1]
            ,imageLoadConfig32.codeIntegrity[2], imageLoadConfig32.guardAddressTakenIatEntryTable
            ,imageLoadConfig32.guardAddressTakenIatEntryCount, imageLoadConfig32.guardLongJumpTargetTable
            ,imageLoadConfig32.guardLongJumpTargetCount
        );
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void parseLoadConfig64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader64[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int64_t* QWORD_Buffer = calloc(8, sizeof(u_int8_t));


    struct _IMAGE_LOAD_CONFIG64 imageLoadConfig64;
    u_int32_t loadConfigOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[10].virtualAddress), numberOfSections, sectionHeader64);

    
    imageLoadConfig64.characteristics = readDWord(file, loadConfigOffset, DWORD_Buffer);
    imageLoadConfig64.timeDateStamp = readDWord(file, loadConfigOffset+4, DWORD_Buffer);
    imageLoadConfig64.majorVersion = readWord(file, loadConfigOffset+8, WORD_Buffer);
    imageLoadConfig64.minorVersion = readWord(file, loadConfigOffset+10, WORD_Buffer);
    imageLoadConfig64.globalFlagsClear = readDWord(file, loadConfigOffset+12, DWORD_Buffer);
    imageLoadConfig64.globalFlagsSet = readDWord(file, loadConfigOffset+16, DWORD_Buffer);
    imageLoadConfig64.criticalSectionDefaultTimeout = readDWord(file, loadConfigOffset+20, DWORD_Buffer);
    imageLoadConfig64.deCommitFreeBlockThreshold = readQWord(file, loadConfigOffset+24, QWORD_Buffer);
    imageLoadConfig64.deCommitTotalFreeThreshold = readQWord(file, loadConfigOffset+32, QWORD_Buffer);
    imageLoadConfig64.lockPrefixTable = readDWord(file, loadConfigOffset+40, DWORD_Buffer);
    imageLoadConfig64.maximumAllocationSize = readQWord(file, loadConfigOffset+48, QWORD_Buffer);
    imageLoadConfig64.virtualMemoryThreshold = readQWord(file, loadConfigOffset+56, QWORD_Buffer);
    imageLoadConfig64.processAffinityMask = readQWord(file, loadConfigOffset+64, QWORD_Buffer);
    imageLoadConfig64.processHeapFlags = readDWord(file, loadConfigOffset+72, DWORD_Buffer);
    imageLoadConfig64.cSDVersion = readWord(file, loadConfigOffset+76, WORD_Buffer);
    imageLoadConfig64.reserved = readWord(file, loadConfigOffset+78, WORD_Buffer);
    imageLoadConfig64.editList = readQWord(file, loadConfigOffset+80, QWORD_Buffer);
    imageLoadConfig64.securityCookie = readQWord(file, loadConfigOffset+88, QWORD_Buffer);
    imageLoadConfig64.sEHandlerTable = readQWord(file, loadConfigOffset+96, QWORD_Buffer);
    imageLoadConfig64.sEHandlerCount = readQWord(file, loadConfigOffset+104, QWORD_Buffer);
    imageLoadConfig64.guardCFCheckFunctionPointer = readQWord(file, loadConfigOffset+110, QWORD_Buffer);
    imageLoadConfig64.guardCFDispatchFunctionPointer = readQWord(file, loadConfigOffset+118, QWORD_Buffer);
    imageLoadConfig64.guardCFFunctionTable = readQWord(file, loadConfigOffset+126, QWORD_Buffer);
    imageLoadConfig64.guardCFFunctionCount = readQWord(file, loadConfigOffset+134, QWORD_Buffer);
    imageLoadConfig64.guardFlags = readDWord(file, loadConfigOffset+142, DWORD_Buffer);
    imageLoadConfig64.codeIntegrity[0] = readDWord(file, loadConfigOffset+146, DWORD_Buffer);
    imageLoadConfig64.codeIntegrity[1] = readDWord(file, loadConfigOffset+150, DWORD_Buffer);
    imageLoadConfig64.codeIntegrity[2] = readDWord(file, loadConfigOffset+154, DWORD_Buffer);
    imageLoadConfig64.guardAddressTakenIatEntryTable = readQWord(file, loadConfigOffset+162, QWORD_Buffer);
    imageLoadConfig64.guardAddressTakenIatEntryCount = readQWord(file, loadConfigOffset+172, QWORD_Buffer);
    imageLoadConfig64.guardLongJumpTargetTable = readQWord(file, loadConfigOffset+180, QWORD_Buffer);
    imageLoadConfig64.guardLongJumpTargetCount = readQWord(file, loadConfigOffset+188, QWORD_Buffer);
    
    if(consoleOutput){
        printf(
            "imageLoadConfig64.characteristics: 0x%04x\n"
            "imageLoadConfig64.timeDateStamp: 0x%04x\n"
            "imageLoadConfig64.majorVersion: 0x%04x\n"
            "imageLoadConfig64.minorVersion: 0x%04x\n"
            "imageLoadConfig64.globalFlagsClear: 0x%04x\n"
            "imageLoadConfig64.globalFlagsSet: 0x%04x\n"
            "imageLoadConfig64.criticalSectionDefaultTimeout: 0x%04x\n"
            "imageLoadConfig64.deCommitFreeBlockThreshold: 0x%04llx\n"
            "imageLoadConfig64.deCommitTotalFreeThreshold: 0x%04llx\n"
            "imageLoadConfig64.lockPrefixTable: 0x%04llx\n"
            "imageLoadConfig64.maximumAllocationSize: 0x%04llx\n"
            "imageLoadConfig64.virtualMemoryThreshold: 0x%04llx\n"
            "imageLoadConfig64.processAffinityMask: 0x%04llx\n"
            "imageLoadConfig64.processHeapFlags: 0x%04x\n"
            "imageLoadConfig64.cSDVersion: 0x%04x\n"
            "imageLoadConfig64.reserved: 0x%04x\n"
            "imageLoadConfig64.editList: 0x%04llx\n"
            "imageLoadConfig64.securityCookie: 0x%04llx\n"
            "imageLoadConfig64.sEHandlerTable: 0x%04llx\n"
            "imageLoadConfig64.sEHandlerCount: 0x%04llx\n"
            "imageLoadConfig64.guardCFCheckFunctionPointer: 0x%04llx\n"
            "imageLoadConfig64.guardCFDispatchFunctionPointer: 0x%04llx\n"
            "imageLoadConfig64.guardCFFunctionTable: 0x%04llx\n"
            "imageLoadConfig64.guardCFFunctionCount: 0x%04llx\n"
            "imageLoadConfig64.guardFlags: 0x%04x\n"
            "imageLoadConfig64.codeIntegrity[0]: 0x%04x\n"
            "imageLoadConfig64.codeIntegrity[1]: 0x%04x\n"
            "imageLoadConfig64.codeIntegrity[2]: 0x%04x\n"
            "imageLoadConfig64.guardAddressTakenIatEntryTable: 0x%04llx\n"
            "imageLoadConfig64.guardAddressTakenIatEntryCount: 0x%04llx\n"
            "imageLoadConfig64.guardLongJumpTargetTable: 0x%04llx\n"
            "imageLoadConfig64.guardLongJumpTargetCount: 0x%04llx\n"
            ,imageLoadConfig64.characteristics, imageLoadConfig64.timeDateStamp
            ,imageLoadConfig64.majorVersion, imageLoadConfig64.minorVersion
            ,imageLoadConfig64.globalFlagsClear, imageLoadConfig64.globalFlagsSet
            ,imageLoadConfig64.criticalSectionDefaultTimeout, imageLoadConfig64.deCommitFreeBlockThreshold
            ,imageLoadConfig64.deCommitTotalFreeThreshold
            ,imageLoadConfig64.lockPrefixTable, imageLoadConfig64.maximumAllocationSize
            ,imageLoadConfig64.virtualMemoryThreshold, imageLoadConfig64.processAffinityMask
            ,imageLoadConfig64.processHeapFlags, imageLoadConfig64.cSDVersion
            ,imageLoadConfig64.reserved, imageLoadConfig64.editList
            ,imageLoadConfig64.securityCookie, imageLoadConfig64.sEHandlerTable
            ,imageLoadConfig64.sEHandlerCount, imageLoadConfig64.guardCFCheckFunctionPointer
            ,imageLoadConfig64.guardCFDispatchFunctionPointer, imageLoadConfig64.guardCFFunctionTable
            ,imageLoadConfig64.guardCFFunctionCount, imageLoadConfig64.guardFlags
            ,imageLoadConfig64.codeIntegrity[0], imageLoadConfig64.codeIntegrity[1]
            ,imageLoadConfig64.codeIntegrity[2], imageLoadConfig64.guardAddressTakenIatEntryTable
            ,imageLoadConfig64.guardAddressTakenIatEntryCount, imageLoadConfig64.guardLongJumpTargetTable
            ,imageLoadConfig64.guardLongJumpTargetCount
        );
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void parseExceptionDirectory32(FILE* file, struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int64_t* QWORD_Buffer = calloc(8, sizeof(u_int8_t));

    struct _IMAGE_EXCEPTION imageException;
    u_int32_t exceptionOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader32.dataDirectory[3].virtualAddress), numberOfSections, sectionHeader);

    imageException.startAddress = readDWord(file, exceptionOffset, DWORD_Buffer);
    imageException.endAddress = readDWord(file, exceptionOffset+4, DWORD_Buffer);
    imageException.unwindAddress = readDWord(file, exceptionOffset+8, DWORD_Buffer);

    while((imageException.startAddress != 0) && (imageException.endAddress != 0) && (imageException.unwindAddress != 0)){
        printf(
            "startAddress: 0x%04x\n"
            "endAddress: 0x%04x\n"
            "unwindAddress: 0x%04x\n"
            ,imageException.startAddress
            ,imageException.endAddress
            ,imageException.unwindAddress
        );
        exceptionOffset += 12;
        imageException.startAddress = readDWord(file, exceptionOffset, DWORD_Buffer);
        imageException.endAddress = readDWord(file, exceptionOffset+4, DWORD_Buffer);
        imageException.unwindAddress = readDWord(file, exceptionOffset+8, DWORD_Buffer);
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void parseExceptionDirectory64(FILE* file, struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64, u_int16_t numberOfSections, struct _SECTION_HEADER sectionHeader64[], struct _IMAGE_COFF_HEADER coffHeader, struct _IMAGE_DOS_HEADER dosHeader, bool consoleOutput){
    u_int8_t* BYTE_Buffer = calloc(1, sizeof(u_int8_t));
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));
    u_int32_t* DWORD_Buffer = calloc(4, sizeof(u_int8_t));
    u_int64_t* QWORD_Buffer = calloc(8, sizeof(u_int8_t));

    struct _IMAGE_EXCEPTION imageException;
    u_int32_t exceptionOffset = convertRelativeAddressToDiskOffset(reverse_endianess_u_int32_t(optionalHeader64.dataDirectory[3].virtualAddress), numberOfSections, sectionHeader64);

    imageException.startAddress = readDWord(file, exceptionOffset, DWORD_Buffer);
    imageException.endAddress = readDWord(file, exceptionOffset+4, DWORD_Buffer);
    imageException.unwindAddress = readDWord(file, exceptionOffset+8, DWORD_Buffer);

    while((imageException.startAddress != 0) && (imageException.endAddress != 0) && (imageException.unwindAddress != 0)){
        printf(
            "startAddress: 0x%04x\n"
            "endAddress: 0x%04x\n"
            "unwindAddress: 0x%04x\n"
            ,imageException.startAddress
            ,imageException.endAddress
            ,imageException.unwindAddress
        );
        exceptionOffset += 12;
        imageException.startAddress = readDWord(file, exceptionOffset, DWORD_Buffer);
        imageException.endAddress = readDWord(file, exceptionOffset+4, DWORD_Buffer);
        imageException.unwindAddress = readDWord(file, exceptionOffset+8, DWORD_Buffer);
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void parsePE(char* pathOfSpecifiedFile, bool exportResult){
    struct _IMAGE_DOS_HEADER dosHeader;
    struct _IMAGE_COFF_HEADER coffHeader;
    struct _IMAGE_OPTIONAL_HEADER32 optionalHeader32;
    struct _IMAGE_OPTIONAL_HEADER64 optionalHeader64;

    FILE* file = fopen(pathOfSpecifiedFile, "rb");
    u_int16_t* WORD_Buffer = calloc(2, sizeof(u_int8_t));

    dosHeader = parseMSDOSHeader(file);
    u_int32_t elfanew = convert_DWORD_To_u_int32_t(dosHeader.e_lfanew);
    coffHeader = parseCoffHeader(file, elfanew);

    
    struct _SECTION_HEADER sectionHeader32[coffHeader.numberOfSections];
    struct _SECTION_HEADER sectionHeader64[coffHeader.numberOfSections];
    u_int16_t sizeOfOptionalHeader = convert_WORD_To_u_int16_t(coffHeader.sizeOfOptionalHeader);
    u_int16_t numberOfSections = convert_WORD_To_u_int16_t(coffHeader.numberOfSections);
    u_int16_t trueMagic = reverse_endianess_u_int16_t(readWord(file, elfanew+24, WORD_Buffer));
    
    switch(trueMagic){
        case 0x10b:
            optionalHeader32 = parseOptionalHeader32(file, elfanew);
            parseSectionHeaders32(file, numberOfSections, sizeOfOptionalHeader, elfanew, sectionHeader32);
            
            if(!exportResult){
                consoleOutput32(dosHeader, coffHeader, optionalHeader32, sectionHeader32, file);
            }
            break;
        case 0x20b:
            optionalHeader64 = parseOptionalHeader64(file, elfanew);
            parseSectionHeaders64(file, numberOfSections, sizeOfOptionalHeader, elfanew, sectionHeader64);

            if(!exportResult){
                consoleOutput64(dosHeader, coffHeader, optionalHeader64, sectionHeader64, file);
            }
            break;
        default:
            printf("ERROR: Unsupported type of image.\n\n");
            break;
    }
}