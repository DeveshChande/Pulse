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

// Common functions used for reading PE32 and PE32+ files.
extern uint8_t reverse_endianess_uint8_t(uint8_t value);
extern uint16_t reverse_endianess_uint16_t(uint16_t value);
extern uint32_t reverse_endianess_uint32_t(uint32_t value);
extern uint64_t reverse_endianess_uint64_t(uint64_t value);
extern uint8_t readByte(FILE* pefile, size_t offset, uint8_t* buffer);
extern uint16_t readWord(FILE* pefile, size_t offset, uint16_t* buffer);
extern uint32_t readDWord(FILE* pefile, size_t offset, uint32_t* buffer);
extern uint64_t readQWord(FILE* pefile, size_t offset, uint64_t* buffer);

// Common functions used for parsing PE32 and PE32+ structures.
extern void initializeMSDOSHeader(struct IMAGE_DOS_HEADER* msDOSHeader);
extern void initializeCoffHeader(struct IMAGE_COFF_HEADER* coffHeader);
extern void parseMSDOSHeader(FILE* pefile, struct IMAGE_DOS_HEADER* msDOSHeader);
extern void parseCoffHeader(FILE* pefile, uint32_t elfanew, struct IMAGE_COFF_HEADER* coffHeader);

// Common functions used for analyzing PE32 and PE32+ files.
extern char* computeMD5Hash(FILE* pefile, char* md5HashValue);
extern char* computeSHA1Hash(FILE* pefile, char* sha1HashValue);
extern char* computeSHA256Hash(FILE* pefile, char* sha256HashValue);
extern void virusTotalResults(char* sha256HashValue, char* apiKey);

#endif