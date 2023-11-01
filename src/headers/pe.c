#include "pe.h"

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

    if(fseek(pefile, (long) offset, SEEK_SET))
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

    if(fseek(pefile, (long) offset, SEEK_SET))
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

    if(fseek(pefile, (long) offset, SEEK_SET))
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

    if(fseek(pefile, (long) offset, SEEK_SET))
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

uint32_t convertRelativeAddressToDiskOffset(uint32_t relativeAddress, uint16_t numberOfSections, struct SECTION_HEADER* sectionHeader){
    size_t i=0;

    for(i=0; i<numberOfSections; i++){
        uint32_t sectionHeaderVirtualAddress = (((sectionHeader[i].virtualAddress&255)&15)*16777216) + (((sectionHeader[i].virtualAddress&255)>>4)*268435456) + ((((sectionHeader[i].virtualAddress>>8)&255)&15)*65536) + ((((sectionHeader[i].virtualAddress>>8)&255)>>4)*1048576) + (((sectionHeader[i].virtualAddress>>16)&15)*256) + ((((sectionHeader[i].virtualAddress>>16)&255)>>4)*4096) + (((sectionHeader[i].virtualAddress>>24)&15)*1) + (((sectionHeader[i].virtualAddress>>24)>>4)*16);
        uint32_t sectionHeaderPointerToRawData = (((sectionHeader[i].pointerToRawData&255)&15)*16777216) + (((sectionHeader[i].pointerToRawData&255)>>4)*268435456) + ((((sectionHeader[i].pointerToRawData>>8)&255)&15)*65536) + ((((sectionHeader[i].pointerToRawData>>8)&255)>>4)*1048576) + (((sectionHeader[i].pointerToRawData>>16)&15)*256) + ((((sectionHeader[i].pointerToRawData>>16)&255)>>4)*4096) + (((sectionHeader[i].pointerToRawData>>24)&15)*1) + (((sectionHeader[i].pointerToRawData>>24)>>4)*16);
        uint32_t sectionHeaderSizeOfRawData = (((sectionHeader[i].sizeOfRawData&255)&15)*16777216) + (((sectionHeader[i].sizeOfRawData&255)>>4)*268435456) + ((((sectionHeader[i].sizeOfRawData>>8)&255)&15)*65536) + ((((sectionHeader[i].sizeOfRawData>>8)&255)>>4)*1048576) + (((sectionHeader[i].sizeOfRawData>>16)&15)*256) + ((((sectionHeader[i].sizeOfRawData>>16)&255)>>4)*4096) + (((sectionHeader[i].sizeOfRawData>>24)&15)*1) + (((sectionHeader[i].sizeOfRawData>>24)>>4)*16);
        
        if((relativeAddress >= sectionHeaderVirtualAddress) && (relativeAddress <= (sectionHeaderVirtualAddress + sectionHeaderSizeOfRawData))){
            return (uint32_t)(sectionHeaderPointerToRawData + relativeAddress - sectionHeaderVirtualAddress);
        }
    }

    return 0;
}

void initializeMSDOSHeader(struct IMAGE_DOS_HEADER* msDOSHeader){
    msDOSHeader->e_magic = (uint16_t)0;
    msDOSHeader->e_cblp = (uint16_t)0;
    msDOSHeader->e_cp = (uint16_t)0;
    msDOSHeader->e_crlc = (uint16_t)0;
    msDOSHeader->e_cparhdr = (uint16_t)0;
    msDOSHeader->e_minalloc = (uint16_t)0;
    msDOSHeader->e_maxalloc = (uint16_t)0;
    msDOSHeader->e_ss = (uint16_t)0;
    msDOSHeader->e_sp = (uint16_t)0;
    msDOSHeader->e_csum = (uint16_t)0;
    msDOSHeader->e_ip = (uint16_t)0;
    msDOSHeader->e_cs = (uint16_t)0;
    msDOSHeader->e_lfarlc = (uint16_t)0;
    msDOSHeader->e_ovno = (uint16_t)0;

    size_t j=0;
    for(size_t i=28;i<=34;i+=2){
        msDOSHeader->e_res[j] = (uint16_t)0;
        j++;
    }

    msDOSHeader->e_oemid = (uint16_t)0;
    msDOSHeader->e_oeminfo = (uint16_t)0;
    
    j=0;
    for(size_t i=40;i<=58;i+=2){
        msDOSHeader->e_res2[j] = (uint16_t)0;
        j++;
    }

    msDOSHeader->e_lfanew = (uint32_t)0;

}

void initializeCoffHeader(struct IMAGE_COFF_HEADER* coffHeader){

    coffHeader->peSignature = (uint32_t)0;
    coffHeader->machine = (uint16_t)0;
    coffHeader->numberOfSections = (uint16_t)0;
    coffHeader->timeDateStamp = (uint32_t)0;
    coffHeader->pointerToSymbolTable = (uint32_t)0;
    coffHeader->numberOfSymbols = (uint32_t)0;
    coffHeader->sizeOfOptionalHeader = (uint16_t)0;
    coffHeader->characteristics = (uint16_t)0;
}

void initializeSectionHeader(uint16_t numberOfSections, struct SECTION_HEADER* sectionHeader){

    for(size_t i=0; i<numberOfSections; i++){
        sectionHeader[i].name = (uint64_t)0;
        sectionHeader[i].virtualSize = (uint32_t)0;
        sectionHeader[i].virtualAddress = (uint32_t)0;
        sectionHeader[i].sizeOfRawData = (uint32_t)0;
        sectionHeader[i].pointerToRawData = (uint32_t)0;
        sectionHeader[i].pointerToRelocations = (uint32_t)0;
        sectionHeader[i].pointerToLineNumbers = (uint32_t)0;
        sectionHeader[i].numberOfRelocations = (uint16_t)0;
        sectionHeader[i].numberOfLineNumbers = (uint16_t)0;
        sectionHeader[i].characteristics = (uint32_t)0;
    }
}

void initializeException(size_t exceptionCount, struct IMAGE_EXCEPTION* exception){
    
    for(size_t i=0;i<exceptionCount;i++){
    	exception[i].startAddress = (uint32_t)0;
    	exception[i].endAddress = (uint32_t)0;
    	exception[i].unwindAddress = (uint32_t)0;
    }
}

void initializeBaseReloc(size_t baseRelocCount, struct IMAGE_BASE_RELOCATION* baseReloc){

    for(size_t i=0;i<baseRelocCount;i++){
        baseReloc[i].pageRVA = (uint32_t)0;
        baseReloc[i].blockSize = (uint32_t)0;
    }

}

void initializeDebug(size_t debugCount, struct IMAGE_DEBUG_DIRECTORY* debug){
    
    for(size_t i=0;i<debugCount;i++){
    	debug[i].characteristics = (uint32_t)0;
        debug[i].timeDateStamp = (uint32_t)0;
        debug[i].majorVersion = (uint16_t)0;
        debug[i].minorVersion = (uint16_t)0;
        debug[i].type = (uint32_t)0;
        debug[i].sizeOfData = (uint32_t)0;
        debug[i].addressOfRawData = (uint32_t)0;
        debug[i].pointerToRawData = (uint32_t)0;
    }
}

void initializeBoundImport(uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR* bounds){
    for(size_t i=0;i<boundsCount;i++){
        bounds[i].timestamp = (uint32_t)0;
        bounds[i].offsetModuleName = (uint16_t)0;
        bounds[i].numberOfModuleForwarderRefs = (uint16_t)0;
    }
}

void parseMSDOSHeader(FILE* pefile, struct IMAGE_DOS_HEADER* msDOSHeader){
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    size_t j = 0;

    msDOSHeader->e_magic = readWord(pefile, 2, WORD_Buffer);
    msDOSHeader->e_cblp = readWord(pefile, 4, WORD_Buffer);
    msDOSHeader->e_cp = readWord(pefile, 6, WORD_Buffer);
    msDOSHeader->e_crlc = readWord(pefile, 9, WORD_Buffer);
    msDOSHeader->e_cparhdr = readWord(pefile, 10, WORD_Buffer);
    msDOSHeader->e_minalloc = readWord(pefile, 12, WORD_Buffer);
    msDOSHeader->e_maxalloc = readWord(pefile, 14, WORD_Buffer);
    msDOSHeader->e_ss = readWord(pefile, 16, WORD_Buffer);
    msDOSHeader->e_sp = readWord(pefile, 18, WORD_Buffer);
    msDOSHeader->e_csum = readWord(pefile, 20, WORD_Buffer);
    msDOSHeader->e_ip = readWord(pefile, 22, WORD_Buffer);
    msDOSHeader->e_cs = readWord(pefile, 24, WORD_Buffer);
    msDOSHeader->e_lfarlc = readWord(pefile, 26, WORD_Buffer);
    msDOSHeader->e_ovno = readWord(pefile, 28, WORD_Buffer);
    
    for(size_t i=28;i<=34;i+=2){
        msDOSHeader->e_res[j] = readWord(pefile, i, WORD_Buffer);
        j++;
    }

    msDOSHeader->e_oemid = readWord(pefile, 36, WORD_Buffer);
    msDOSHeader->e_oeminfo = readWord(pefile, 38, WORD_Buffer);
    
    j=0;
    for(size_t i=40;i<=58;i+=2){
        msDOSHeader->e_res2[j] = readWord(pefile, i, WORD_Buffer);
        j++;
    }

    msDOSHeader->e_lfanew = readDWord(pefile, 60, DWORD_Buffer);

    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseCoffHeader(FILE* file, uint32_t elfanew, struct IMAGE_COFF_HEADER* coffHeader){
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
            coffHeader->machineArchitecture[26] = '\0';
            break;
        case 0x1d3:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_AM33", 24);
            coffHeader->machineArchitecture[23] = '\0';
            break;
        case 0x8664:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_AMD64", 25);
            coffHeader->machineArchitecture[24] = '\0';
            break;
        case 0x1c0:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_ARM", 23);
            coffHeader->machineArchitecture[23] = '\0';
            break;
        case 0xaa64:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_ARM64", 25);
            coffHeader->machineArchitecture[24] = '\0';
            break;
        case 0x1c4:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_ARMNT", 25);
            coffHeader->machineArchitecture[24] = '\0';
            break;
        case 0xebc:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_EBC", 23);
            coffHeader->machineArchitecture[22] = '\0';
            break;
        case 0x14c:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_I386", 24);
            coffHeader->machineArchitecture[23] = '\0';
            break;
        case 0x200:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_IA64", 24);
            coffHeader->machineArchitecture[23] = '\0';
            break;
        case 0x6232:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_LOONGARCH32", 31);
            coffHeader->machineArchitecture[30] = '\0';
            break;
        case 0x6264:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_LOONGARCH64", 31);
            coffHeader->machineArchitecture[30] = '\0';
            break;
        case 0x9041:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_M32R", 24);
            coffHeader->machineArchitecture[23] = '\0';
            break;
        case 0x266:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_MIPS16", 26);
            coffHeader->machineArchitecture[25] = '\0';
            break;
        case 0x366:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_MIPSFPU", 27);
            coffHeader->machineArchitecture[26] = '\0';
            break;
        case 0x1f0:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_POWERPC", 27);
            coffHeader->machineArchitecture[26] = '\0';
            break;
        case 0x1f1:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_POWERPCFP", 29);
            coffHeader->machineArchitecture[28] = '\0';
            break;
        case 0x166:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_R4000", 25);
            coffHeader->machineArchitecture[24] = '\0';
            break;
        case 0x5032:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_RISCV32", 27);
            coffHeader->machineArchitecture[26] = '\0';
            break;
        case 0x5064:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_RISCV64", 27);
            coffHeader->machineArchitecture[26] = '\0';
            break;
        case 0x5128:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_RISCV128", 28);
            coffHeader->machineArchitecture[27] = '\0';
            break;
        case 0x1a2:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_SH3", 23);
            coffHeader->machineArchitecture[22] = '\0';
            break;
        case 0x1a3:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_SH3DSP", 26);
            coffHeader->machineArchitecture[25] = '\0';
            break;
        case 0x1a6:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_SH4", 23);
            coffHeader->machineArchitecture[22] = '\0';
            break;
        case 0x1a8:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_SH5", 23);
            coffHeader->machineArchitecture[22] = '\0';
            break;
        case 0x1c2:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_THUMB", 25);
            coffHeader->machineArchitecture[24] = '\0';
            break;
        case 0x169:
            memcpy(coffHeader->machineArchitecture, "IMAGE_FILE_MACHINE_WCEMIPSV2", 29);
            coffHeader->machineArchitecture[28] = '\0';
            break;
        default:
            memcpy(coffHeader->machineArchitecture, "UNDEFINED_ARCHITECTURE_ANOMALY", 31);
            coffHeader->machineArchitecture[30] = '\0';
            break;
    }

    uint16_t imageFileCharacteristics[16] = {1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768};
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
                (coffHeader->characteristicsList[i])[26] = '\0';
                break;
            case 2:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_EXECUTABLE_IMAGE", 28);
                (coffHeader->characteristicsList[i])[27] = '\0';
                break;
            case 4:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_LINE_NUMS_STRIPPED", 30);
                (coffHeader->characteristicsList[i])[29] = '\0';
                break;
            case 8:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_LOCAL_SYMS_STRIPPED", 31);
                (coffHeader->characteristicsList[i])[30] = '\0';
                break;
            case 16:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_AGGRESSIVE_WS_TRIM", 30);
                (coffHeader->characteristicsList[i])[29] = '\0';
                break;
            case 32:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_LARGE_ADDRESS_AWARE", 31);
                (coffHeader->characteristicsList[i])[30] = '\0';
                break;
            case 64:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_FUTURE_USE", 22);
                (coffHeader->characteristicsList[i])[21] = '\0';
                break;
            case 128:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_BYTES_REVERSED_LO", 29);
                (coffHeader->characteristicsList[i])[28] = '\0';
                break;
            case 256:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_32BIT_MACHINE", 25);
                (coffHeader->characteristicsList[i])[24] = '\0';
                break;
            case 512:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_DEBUG_STRIPPED", 26);
                (coffHeader->characteristicsList[i])[25] = '\0';
                break;
            case 1024:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_REMOVABLE_RUN_", 26);
                (coffHeader->characteristicsList[i])[25] = '\0';
                break;
            case 2048:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_NET_RUN_FROM_SWAP", 29);
                (coffHeader->characteristicsList[i])[28] = '\0';
                break;
            case 4096:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_SYSTEM", 18);
                (coffHeader->characteristicsList[i])[17] = '\0';
                break;
            case 8192:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_DLL", 15);
                (coffHeader->characteristicsList[i])[14] = '\0';
                break;
            case 16384:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_UP_SYSTEM_ONLY", 26);
                (coffHeader->characteristicsList[i])[25] = '\0';
                break;
            case 32768:
                memcpy(coffHeader->characteristicsList[i], "IMAGE_FILE_BYTES_REVERSED_HI", 29);
                (coffHeader->characteristicsList[i])[28] = '\0';
                break;
            default:
                memcpy(coffHeader->characteristicsList[i], "UNKNOWN_CHARACTERISTICS_ANOMALY", 32);
                (coffHeader->characteristicsList[i])[31] = '\0';
                break;
        }
    }

    free(savedCharacteristics);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void parseSectionHeaders(FILE* pefile, uint16_t numberOfSections, uint32_t memoryOffset, struct SECTION_HEADER* sectionHeader){

    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));

    for(size_t i=0; i<numberOfSections; i++){
        sectionHeader[i].name = readQWord(pefile, memoryOffset+i*40, QWORD_Buffer);
        sectionHeader[i].virtualSize = readDWord(pefile, memoryOffset+i*40+8, DWORD_Buffer);
        sectionHeader[i].virtualAddress = readDWord(pefile, memoryOffset+i*40+12, DWORD_Buffer);
        sectionHeader[i].sizeOfRawData = readDWord(pefile, memoryOffset+i*40+16, DWORD_Buffer);
        sectionHeader[i].pointerToRawData = readDWord(pefile, memoryOffset+i*40+20, DWORD_Buffer);
        sectionHeader[i].pointerToRelocations = readDWord(pefile, memoryOffset+i*40+24, DWORD_Buffer);
        sectionHeader[i].pointerToLineNumbers = readDWord(pefile, memoryOffset+i*40+28, DWORD_Buffer);
        sectionHeader[i].numberOfRelocations = readWord(pefile, memoryOffset+i*40+32, WORD_Buffer);
        sectionHeader[i].numberOfLineNumbers = readWord(pefile, memoryOffset+i*40+34, WORD_Buffer);
        sectionHeader[i].characteristics = readDWord(pefile, memoryOffset+i*40+36, DWORD_Buffer);
    }
    
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void parseException(FILE* pefile, uint32_t diskOffset, size_t exceptionCount, struct IMAGE_EXCEPTION* exception){
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    
    for(size_t i=0;i<exceptionCount;i++){
    	exception[i].startAddress = readDWord(pefile, diskOffset, DWORD_Buffer);
    	exception[i].endAddress = readDWord(pefile, diskOffset+4, DWORD_Buffer);
    	exception[i].unwindAddress = readDWord(pefile, diskOffset+8, DWORD_Buffer);
    	diskOffset += 12;
    }
    
    free(DWORD_Buffer);
}

void parseBaseReloc(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION* baseReloc){

    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));

    size_t i=0, typeCount=0;

    while(i < baseRelocCount){
        baseReloc[i].pageRVA = reverse_endianess_uint32_t(readDWord(pefile, diskOffset, DWORD_Buffer));
        baseReloc[i].blockSize = reverse_endianess_uint32_t(readDWord(pefile, diskOffset+4, DWORD_Buffer));
        diskOffset += 8;
        typeCount = (baseReloc[i].blockSize - 8) / 2;  	
    	diskOffset += (uint32_t) (typeCount * sizeof(WORD));
    	i++;
    }

    free(DWORD_Buffer);
}

void parseDebug(FILE* pefile, size_t debugCount, uint32_t diskOffset, struct IMAGE_DEBUG_DIRECTORY* debug){
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    
    for(size_t i=0;i<debugCount;i++){
    	debug[i].characteristics = readDWord(pefile, diskOffset, DWORD_Buffer);
        debug[i].timeDateStamp = readDWord(pefile, diskOffset+4, DWORD_Buffer);
        debug[i].majorVersion = readWord(pefile, diskOffset+8, WORD_Buffer);
        debug[i].minorVersion = readWord(pefile, diskOffset+10, WORD_Buffer);
        debug[i].type = readDWord(pefile, diskOffset+12, DWORD_Buffer);
        debug[i].sizeOfData = readDWord(pefile, diskOffset+16, DWORD_Buffer);
        debug[i].addressOfRawData = readDWord(pefile, diskOffset+20, DWORD_Buffer);
        debug[i].pointerToRawData = readDWord(pefile, diskOffset+24, DWORD_Buffer);
        diskOffset += 28;
    }
    
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);

}

void parseBoundImport(FILE* pefile, uint32_t diskOffset, uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR* bounds){
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    size_t i=0;
    
    bounds[i].timestamp = readDWord(pefile, diskOffset, DWORD_Buffer);
    bounds[i].offsetModuleName = readWord(pefile, diskOffset+4, WORD_Buffer);
    bounds[i].numberOfModuleForwarderRefs = readWord(pefile, diskOffset+6, WORD_Buffer);
    boundsCount++;
    diskOffset += 8;
    	
    while((bounds[i].timestamp != 0) && (bounds[i].offsetModuleName != 0) && (bounds[i].numberOfModuleForwarderRefs != 0)){
    		
    	if(bounds[i].numberOfModuleForwarderRefs != 0){
    		struct IMAGE_BOUND_FORWARDER_REF tmpForwards;
            tmpForwards.timestamp = 1;
            tmpForwards.offsetModuleName = 1;
            tmpForwards.reserved= 1;

    		while((tmpForwards.timestamp != 0) && (tmpForwards.offsetModuleName != 0) && (tmpForwards.reserved != 0)){
    			tmpForwards.timestamp = readDWord(pefile, diskOffset, DWORD_Buffer);
    			tmpForwards.offsetModuleName = readWord(pefile, diskOffset+4, WORD_Buffer);
    			tmpForwards.reserved = readWord(pefile, diskOffset+6, WORD_Buffer);
    			diskOffset += 8;
    		}
    	}
    		
    	boundsCount++;
    	diskOffset += 8;
    		
    	bounds[i].timestamp = readDWord(pefile, diskOffset, DWORD_Buffer);
    	bounds[i].offsetModuleName = readWord(pefile, diskOffset+4, WORD_Buffer);
    	bounds[i++].numberOfModuleForwarderRefs = readWord(pefile, diskOffset+6, WORD_Buffer);
    }    
    
    free(WORD_Buffer);
    free(DWORD_Buffer);

}

void exceptionConsoleOutput(size_t exceptionCount, struct IMAGE_EXCEPTION* exception){

	printf("Exception Table\n-----------------------------\n");	

	for(size_t i=0;i<exceptionCount;i++){
    	    printf("exception[%zu].startAddress: %04x\n", i, exception[i].startAddress);
    	    printf("exception[%zu].endAddress: %04x\n", i, exception[i].endAddress);
    	    printf("exception[%zu].unwindAddress: %04x\n", i, exception[i].unwindAddress);
        }

	printf("\n");

}

void baseRelocConsoleOutput(FILE* pefile, uint32_t diskOffset, size_t baseRelocCount, struct IMAGE_BASE_RELOCATION* baseReloc){
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    
    char* baseRelocTypes[4] = {"IMAGE_REL_BASED_ABSOLUTE", "IMAGE_REL_BASED_HIGH", "IMAGE_REL_BASED_LOW", "IMAGE_REL_BASED_HIGHLOW"};

    size_t i=0, typeCount=0;
    
    printf("BASE RELOCATIONS\n---------------------------\n\n");
    
    while(i < baseRelocCount){
    	printf("baseReloc->pageRVA: %04x\n", baseReloc[i].pageRVA);
    	printf("baseReloc->blockSize: %04x\n", baseReloc[i].blockSize);
    	typeCount = (baseReloc[i].blockSize - 8) / 2;
    	diskOffset += (uint32_t)(2 * sizeof(DWORD));
    	printf("diskOffset: %04x\n", diskOffset + (uint32_t)(2*sizeof(DWORD)));
        printf("---------------------------\n");
        uint16_t fourbitValue = 0;
        uint16_t twelvebitValue = 0;        

        while(typeCount--){
            fourbitValue = (reverse_endianess_uint16_t(readWord(pefile, diskOffset, WORD_Buffer)) >> 12);
            twelvebitValue = (reverse_endianess_uint16_t(readWord(pefile, diskOffset, WORD_Buffer)) & 0x0FFF);
            if(fourbitValue < 4){
            	printf(
                    "\t[type: 0x%02x\t(%s)]"
                    "\taddress: 0x%04x\n"
                    ,(fourbitValue), baseRelocTypes[fourbitValue] , (uint32_t)(twelvebitValue)+baseReloc[i].pageRVA
                );
            }
            else{
                printf(
                    "\t[type: 0x%02x]"
                    "\taddress: 0x%04x\n"
                    ,(fourbitValue), (uint32_t)(twelvebitValue)+baseReloc[i].pageRVA
                );
            }
            diskOffset += sizeof(WORD);
        }
	printf("\n");
        baseReloc[i].pageRVA = reverse_endianess_uint32_t(readDWord(pefile, diskOffset, DWORD_Buffer));
        baseReloc[i++].blockSize = reverse_endianess_uint32_t(readDWord(pefile, diskOffset+4, DWORD_Buffer));
    }

    free(WORD_Buffer);
    free(DWORD_Buffer);
}

void debugConsoleOutput(FILE* pefile, size_t debugCount, struct IMAGE_DEBUG_DIRECTORY* debug, struct SECTION_HEADER* sectionHeader){
    
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    
    char* debugTypes[17] = {"IMAGE_DEBUG_TYPE_UNKNOWN", "IMAGE_DEBUG_TYPE_COFF", "IMAGE_DEBUG_TYPE_CODEVIEW", "IMAGE_DEBUG_TYPE_FPO", "IMAGE_DEBUG_TYPE_MISC", "IMAGE_DEBUG_TYPE_EXCEPTION", "IMAGE_DEBUG_TYPE_FIXUP", "IMAGE_DEBUG_TYPE_OMAP_TO_SRC", "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC", "IMAGE_DEBUG_TYPE_BORLAND", "IMAGE_DEBUG_TYPE_RESERVED10", "IMAGE_DEBUG_TYPE_CLSID", "IMAGE_DEBUG_TYPE_VC_FEATURE", "IMAGE_DEBUG_TYPE_POGO", "IMAGE_DEBUG_TYPE_ILTCG", "IMAGE_DEBUG_TYPE_MPX", "IMAGE_DEBUG_TYPE_REPRO"};
    
    
    printf("DEBUG INFORMATION\n--------------------------------\n\n");
    
    for(size_t i=0;i<debugCount;i++){
    	printf("debug[%zu]->characteristics: %04x\n", i, reverse_endianess_uint32_t(debug[i].characteristics));
    	printf("debug[%zu]->timeDateStamp: %04x\n", i, reverse_endianess_uint32_t(debug[i].timeDateStamp));
    	printf("debug[%zu]->majorVersio: %02x\n", i, reverse_endianess_uint16_t(debug[i].majorVersion));
    	printf("debug[%zu]->minorVersion: %02x\n", i, reverse_endianess_uint16_t(debug[i].minorVersion));
    	printf("debug[%zu]->type: %04x\n", i, reverse_endianess_uint32_t(debug[i].type));
    	printf("debug[%zu]->sizeOfData: %04x\n", i, reverse_endianess_uint32_t(debug[i].sizeOfData));
    	printf("debug[%zu]->addressOfRawData: %04x\n", i, reverse_endianess_uint32_t(debug[i].addressOfRawData));
    	printf("debug[%zu]->pointerToRawData: %04x\n", i, reverse_endianess_uint32_t(debug[i].pointerToRawData));
    
    
    	uint32_t cvSignatureOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(debug[i].addressOfRawData), (uint16_t)debugCount, sectionHeader);
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
     	
     	printf("%s\n\n", debugTypes[reverse_endianess_uint32_t(debug[i].type)]);
     
     }
     
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);

}

void boundsConsoleOutput(uint32_t boundsCount, struct IMAGE_BOUND_IMPORT_DESCRIPTOR* bounds){
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));

    printf("BOUND IMPORTS\n------------------\n");
    for(size_t i=0;i<boundsCount;i++){
    	printf("bounds[%zu].timestamp: %04x\n", i, bounds[i].timestamp);
    	printf("bounds[%zu].offsetModuleName (RVA): %02x\n", i, bounds[i].offsetModuleName);
    	printf("bounds[%zu].numberOfModuleForwarderRefs: %02x\n", i, bounds[i].numberOfModuleForwarderRefs);
    	i++;
    }

    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
}

char* computeMD5Hash(FILE* pefile, char* md5HashValue){

    size_t n=0;
    char md5buff[4096];
    unsigned char md5digestValue[EVP_MAX_MD_SIZE];
    unsigned int md5digestLength;
    fseek(pefile, 0, SEEK_SET);
    
    EVP_MD_CTX* md5mdctx = EVP_MD_CTX_new();
    if(md5mdctx == NULL){
    	perror("Failed to configure library context");
    }
    
    EVP_DigestInit_ex(md5mdctx, EVP_md5(), NULL);
    while ((n = fread(md5buff, 1, sizeof(md5buff), pefile)))
    {
            EVP_DigestUpdate(md5mdctx, md5buff, n);
    }
    
    EVP_DigestFinal_ex(md5mdctx, md5digestValue, &md5digestLength);
    
    size_t j=0;
    for (size_t i = 0; i < md5digestLength; i++)
    {
    	    char tmp[3] = {0};
    	    sprintf(tmp, "%02x", md5digestValue[i]);
    	    tmp[2] = '\0';
            md5HashValue[j++] = tmp[0];
            md5HashValue[j++] = tmp[1];
    }
    
    md5HashValue[32] = '\0';
    EVP_MD_CTX_free(md5mdctx);
    return md5HashValue;

}

char* computeSHA1Hash(FILE* pefile, char* sha1HashValue){

    size_t n=0;
    char sha1buff[4096];
    unsigned char sha1digestValue[EVP_MAX_MD_SIZE];
    unsigned int sha1digestLength;
    fseek(pefile, 0, SEEK_SET);
    
    EVP_MD_CTX* sha1mdctx = EVP_MD_CTX_new();
    if(sha1mdctx == NULL){
    	perror("Failed to configure library context");
    }
    
    EVP_DigestInit_ex(sha1mdctx, EVP_sha1(), NULL);
    while ((n = fread(sha1buff, 1, sizeof(sha1buff), pefile)))
    {
            EVP_DigestUpdate(sha1mdctx, sha1buff, n);
    }
    
    EVP_DigestFinal_ex(sha1mdctx, sha1digestValue, &sha1digestLength);

    size_t j=0;
    for (size_t i = 0; i < sha1digestLength; i++)
    {
    	    char tmp[3] = {0};
    	    sprintf(tmp, "%02x", sha1digestValue[i]);
    	    tmp[2] = '\0';
            sha1HashValue[j++] = tmp[0];
            sha1HashValue[j++] = tmp[1];
    }
    
    sha1HashValue[40] = '\0';
    EVP_MD_CTX_free(sha1mdctx);
    return sha1HashValue;
    
}


char* computeSHA256Hash(FILE* pefile, char* sha256HashValue){
    size_t n=0;
    char sha256buff[4096];
    unsigned char sha256digestValue[EVP_MAX_MD_SIZE];
    unsigned int sha256digestLength;
    fseek(pefile, 0, SEEK_SET);
    
    EVP_MD_CTX* sha256mdctx = EVP_MD_CTX_new();
    if(sha256mdctx == NULL){
    	perror("Failed to configure library context");
    }
    
    EVP_DigestInit_ex(sha256mdctx, EVP_sha256(), NULL);
    while ((n = fread(sha256buff, 1, sizeof(sha256buff), pefile)))
    {
            EVP_DigestUpdate(sha256mdctx, sha256buff, n);
    }
    
    EVP_DigestFinal_ex(sha256mdctx, sha256digestValue, &sha256digestLength);
   
    size_t j=0;
    for (size_t i = 0; i < sha256digestLength; i++)
    {
    	    char tmp[3] = {0};
    	    sprintf(tmp, "%02x", sha256digestValue[i]);
    	    tmp[2] = '\0';
            sha256HashValue[j++] = tmp[0];
            sha256HashValue[j++] = tmp[1];
    }
    sha256HashValue[64] = '\0';
    EVP_MD_CTX_free(sha256mdctx);
    return sha256HashValue;
    
}

void virusTotalResults(char* sha256HashValue, char* apiKey){

printf("\n\nVirusTotal Results:\n------------------------------------\n");

char apiUrl[106] = {0};
const char* baseUrl = "https://www.virustotal.com/api/v3/files/";
sprintf(apiUrl, "%s%s", baseUrl, sha256HashValue);

curl_global_init(CURL_GLOBAL_DEFAULT);
CURL *hnd = curl_easy_init();

curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
curl_easy_setopt(hnd, CURLOPT_URL, apiUrl);

struct curl_slist *headers = NULL;
headers = curl_slist_append(headers, "accept: application/json");

char xAPIKey[75] = {0};
sprintf(xAPIKey, "%s%s", "x-apikey: ", apiKey);
headers = curl_slist_append(headers, xAPIKey);
curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

CURLcode ret = curl_easy_perform(hnd);

if(ret != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(ret));

curl_slist_free_all(headers);
curl_easy_cleanup(hnd);
curl_global_cleanup();
}