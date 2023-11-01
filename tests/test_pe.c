#include "test_pe.h"

void test_initializeMSDOSHeader(void** state){
    struct IMAGE_DOS_HEADER* msDOSHeader = malloc(sizeof(struct IMAGE_DOS_HEADER));

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

    for(size_t i=0;i<4;i++){
        msDOSHeader->e_res[i] = (uint16_t)0;
    }

    msDOSHeader->e_oemid = (uint16_t)0;
    msDOSHeader->e_oeminfo = (uint16_t)0;
    
    for(size_t i=0;i<10;i++){
        msDOSHeader->e_res2[i] = (uint16_t)0;
    }

    msDOSHeader->e_lfanew = (uint32_t)0;

    assert_int_equal(msDOSHeader->e_magic, 0);
    assert_int_equal(msDOSHeader->e_cblp, 0);
    assert_int_equal(msDOSHeader->e_cp, 0);
    assert_int_equal(msDOSHeader->e_crlc, 0);
    assert_int_equal(msDOSHeader->e_cparhdr, 0);
    assert_int_equal(msDOSHeader->e_minalloc, 0);
    assert_int_equal(msDOSHeader->e_maxalloc, 0);
    assert_int_equal(msDOSHeader->e_ss, 0);
    assert_int_equal(msDOSHeader->e_sp, 0);
    assert_int_equal(msDOSHeader->e_csum, 0);
    assert_int_equal(msDOSHeader->e_cs, 0);
    assert_int_equal(msDOSHeader->e_lfarlc, 0);
    assert_int_equal(msDOSHeader->e_ovno, 0);
    assert_int_equal(msDOSHeader->e_magic, 0);
    assert_int_equal(msDOSHeader->e_magic, 0);
    assert_int_equal(msDOSHeader->e_magic, 0);
    assert_int_equal(msDOSHeader->e_magic, 0);
    assert_int_equal(msDOSHeader->e_magic, 0);
    assert_int_equal(msDOSHeader->e_magic, 0);
    assert_int_equal(msDOSHeader->e_magic, 0);

    for(size_t i=0;i<4;i++){
        assert_int_equal(msDOSHeader->e_res[i], 0);
    }

    assert_int_equal(msDOSHeader->e_oemid, 0);
    assert_int_equal(msDOSHeader->e_oeminfo, 0);

    for(size_t i=0;i<10;i++){
        assert_int_equal(msDOSHeader->e_res2[i], 0);
    }

    assert_int_equal(msDOSHeader->e_lfanew, 0);

    free(msDOSHeader);
    (void) state;
}

void test_initializeCoffHeader(void** state){
    struct IMAGE_COFF_HEADER* coffHeader = malloc(sizeof(struct IMAGE_COFF_HEADER));

    coffHeader->peSignature = (uint32_t)0;
    coffHeader->machine = (uint16_t)0;
    coffHeader->numberOfSections = (uint16_t)0;
    coffHeader->timeDateStamp = (uint32_t)0;
    coffHeader->pointerToSymbolTable = (uint32_t)0;
    coffHeader->numberOfSymbols = (uint32_t)0;
    coffHeader->sizeOfOptionalHeader = (uint16_t)0;
    coffHeader->characteristics = (uint16_t)0;

    assert_int_equal(coffHeader->peSignature, 0);
    assert_int_equal(coffHeader->machine, 0);
    assert_int_equal(coffHeader->numberOfSections, 0);
    assert_int_equal(coffHeader->timeDateStamp, 0);
    assert_int_equal(coffHeader->pointerToSymbolTable, 0);
    assert_int_equal(coffHeader->numberOfSymbols, 0);
    assert_int_equal(coffHeader->sizeOfOptionalHeader, 0);
    assert_int_equal(coffHeader->characteristics, 0);

    free(coffHeader);
    (void) state;
}

void test_initializeSectionHeader(void** state){
    uint16_t numberOfSections = 4;
    struct SECTION_HEADER* sectionHeader = malloc(sizeof(struct SECTION_HEADER) * numberOfSections);

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


    for(size_t i=0; i<numberOfSections; i++){
        assert_int_equal(sectionHeader[i].name, 0);
        assert_int_equal(sectionHeader[i].virtualSize, 0);
        assert_int_equal(sectionHeader[i].virtualAddress, 0);
        assert_int_equal(sectionHeader[i].sizeOfRawData, 0);
        assert_int_equal(sectionHeader[i].pointerToRawData, 0);
        assert_int_equal(sectionHeader[i].pointerToRelocations, 0);
        assert_int_equal(sectionHeader[i].pointerToLineNumbers, 0);
        assert_int_equal(sectionHeader[i].numberOfRelocations, 0);
        assert_int_equal(sectionHeader[i].numberOfLineNumbers, 0);
        assert_int_equal(sectionHeader[i].characteristics, 0);
    }
    
    free(sectionHeader);
    (void) state;
}

void test_initializeException(void** state){

    size_t exceptionCount = 5;
    struct IMAGE_EXCEPTION* exception = malloc(sizeof(struct IMAGE_EXCEPTION) * exceptionCount);

    for(size_t i=0;i<exceptionCount;i++){
    	exception[i].startAddress = (uint32_t)0;
    	exception[i].endAddress = (uint32_t)0;
    	exception[i].unwindAddress = (uint32_t)0;
    }

    for(size_t i=0;i<exceptionCount;i++){
    	assert_int_equal(exception[i].startAddress, 0);
    	assert_int_equal(exception[i].endAddress, 0);
    	assert_int_equal(exception[i].unwindAddress, 0);
    }

    free(exception);
    (void) state;
}

void test_initializeBaseReloc(void** state){

    size_t baseRelocCount = 10;
    struct IMAGE_BASE_RELOCATION* baseReloc = malloc(sizeof(struct IMAGE_BASE_RELOCATION) * baseRelocCount);

    for(size_t i=0;i<baseRelocCount;i++){
        baseReloc[i].pageRVA = (uint32_t)0;
        baseReloc[i].blockSize = (uint32_t)0;
    }

    for(size_t i=0;i<baseRelocCount;i++){
        assert_int_equal(baseReloc[i].pageRVA, 0);
        assert_int_equal(baseReloc[i].blockSize, 0);
    }

    free(baseReloc);
    (void) state;
}

void test_initializeDebug(void** state){

    size_t debugCount = 7;
    struct IMAGE_DEBUG_DIRECTORY* debug = malloc(sizeof(struct IMAGE_DEBUG_DIRECTORY) * debugCount);

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

    for(size_t i=0;i<debugCount;i++){
    	assert_int_equal(debug[i].characteristics, 0);
        assert_int_equal(debug[i].timeDateStamp, 0);
        assert_int_equal(debug[i].majorVersion, 0);
        assert_int_equal(debug[i].minorVersion, 0);
        assert_int_equal(debug[i].type, 0);
        assert_int_equal(debug[i].sizeOfData, 0);
        assert_int_equal(debug[i].addressOfRawData, 0);
        assert_int_equal(debug[i].pointerToRawData, 0);
    }

    free(debug);
    (void) state;
}

void test_initializeBoundImport(void** state){

    uint32_t boundsCount = 4;
    struct IMAGE_BOUND_IMPORT_DESCRIPTOR* bounds = malloc(sizeof(struct IMAGE_BOUND_IMPORT_DESCRIPTOR) * boundsCount);
    
    for(size_t i=0;i<boundsCount;i++){
        bounds[i].timestamp = (uint32_t)0;
        bounds[i].offsetModuleName = (uint16_t)0;
        bounds[i].numberOfModuleForwarderRefs = (uint16_t)0;
    }

    for(size_t i=0;i<boundsCount;i++){
        bounds[i].timestamp = (uint32_t)0;
        bounds[i].offsetModuleName = (uint16_t)0;
        bounds[i].numberOfModuleForwarderRefs = (uint16_t)0;
    }

    free(bounds);
    (void) state;
}