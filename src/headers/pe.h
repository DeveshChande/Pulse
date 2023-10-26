#include <stdint.h>
#include <openssl/evp.h>
#include <curl/curl.h>

#ifndef PE_CF
#define PE_CF

// Typedef definitions

typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t QWORD;
typedef BYTE *LPBYTE;
typedef WORD *PDWORD;

// Common structures for PE32 and PE32+.
struct IMAGE_DOS_HEADER{
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

struct IMAGE_COFF_HEADER{
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

struct EXPORT_DATA_DIRECTORY{
    DWORD virtualAddress;
    DWORD size;
};

struct IMAGE_EXCEPTION{
    DWORD startAddress;
    DWORD endAddress;
    DWORD unwindAddress;
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

struct IMAGE_BASE_RELOCATION{
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

struct GUID{
  DWORD Data1;
  WORD Data2;
  WORD Data3;
  BYTE Data4[8];
};

struct CV_HEADER{
  DWORD Signature;
  DWORD Offset;
};

struct CV_INFO_PDB20{
  struct CV_HEADER header;
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

struct IMAGE_DEBUG_DIRECTORY{
  DWORD characteristics;
  DWORD timeDateStamp;
  WORD  majorVersion;
  WORD  minorVersion;
  DWORD type;
  DWORD sizeOfData;
  DWORD addressOfRawData;
  DWORD pointerToRawData;
};

struct IMAGE_BOUND_IMPORT_DESCRIPTOR{
    DWORD timestamp;
    WORD offsetModuleName;
    WORD numberOfModuleForwarderRefs;
};

struct IMAGE_BOUND_FORWARDER_REF{
    DWORD timestamp;
    WORD offsetModuleName;
    WORD reserved;
};

struct SECTION_HEADER{
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

// Common functions used for reading PE32 and PE32+ files.
extern uint8_t reverse_endianess_uint8_t(uint8_t value);
extern uint16_t reverse_endianess_uint16_t(uint16_t value);
extern uint32_t reverse_endianess_uint32_t(uint32_t value);
extern uint64_t reverse_endianess_uint64_t(uint64_t value);
extern uint8_t readByte(FILE* pefile, size_t offset, uint8_t* buffer);
extern uint16_t readWord(FILE* pefile, size_t offset, uint16_t* buffer);
extern uint32_t readDWord(FILE* pefile, size_t offset, uint32_t* buffer);
extern uint64_t readQWord(FILE* pefile, size_t offset, uint64_t* buffer);
extern uint32_t convertRelativeAddressToDiskOffset(uint32_t relativeAddress, uint16_t numberOfSections, struct SECTION_HEADER* sectionHeader);

// Common functions used for parsing PE32 and PE32+ structures.
extern void initializeMSDOSHeader(struct IMAGE_DOS_HEADER* msDOSHeader);
extern void initializeCoffHeader(struct IMAGE_COFF_HEADER* coffHeader);
extern void initializeSectionHeader(uint16_t numberOfSections, struct SECTION_HEADER* sectionHeader);
extern void initializeException(size_t exceptionCount, struct IMAGE_EXCEPTION* exception);
extern void initializeBaseReloc(size_t baseRelocCount, struct IMAGE_BASE_RELOCATION* baseReloc);
extern void initializeDebug(size_t debugCount, struct IMAGE_DEBUG_DIRECTORY* debug);
extern void initializeBoundImport(uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR* bounds);

extern void parseMSDOSHeader(FILE* pefile, struct IMAGE_DOS_HEADER* msDOSHeader);
extern void parseCoffHeader(FILE* pefile, uint32_t elfanew, struct IMAGE_COFF_HEADER* coffHeader);
extern void parseSectionHeaders(FILE* pefile, uint16_t numberOfSections, uint32_t memoryOffset, struct SECTION_HEADER* sectionHeader);
extern void parseException(FILE* pefile, uint32_t diskOffset, size_t exceptionCount, struct IMAGE_EXCEPTION* exception);
extern void parseBaseReloc(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION* baseReloc);
extern void parseDebug(FILE* pefile, size_t debugCount, uint32_t diskOffset, struct IMAGE_DEBUG_DIRECTORY* debug);
extern void parseBoundImport(FILE* pefile, uint32_t diskOffset, uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR* bounds);

extern void exceptionConsoleOutput(size_t exceptionCount, struct IMAGE_EXCEPTION* exception);
extern void baseRelocConsoleOutput(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION* baseReloc);
extern void debugConsoleOutput(FILE* pefile, size_t debugCount, struct IMAGE_DEBUG_DIRECTORY* debug, struct SECTION_HEADER* sectionHeader);
extern void boundsConsoleOutput(uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR* bounds);

// Common functions used for analyzing PE32 and PE32+ files.
extern char* computeMD5Hash(FILE* pefile, char* md5HashValue);
extern char* computeSHA1Hash(FILE* pefile, char* sha1HashValue);
extern char* computeSHA256Hash(FILE* pefile, char* sha256HashValue);
extern void virusTotalResults(char* sha256HashValue, char* apiKey);

#endif