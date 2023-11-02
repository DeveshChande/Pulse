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
    assert_int_equal(msDOSHeader->e_ip, 0);
    assert_int_equal(msDOSHeader->e_cs, 0);
    assert_int_equal(msDOSHeader->e_lfarlc, 0);
    assert_int_equal(msDOSHeader->e_ovno, 0);
    

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

void test_parseMSDOSHeader(void** state){
    
    FILE* pefile = fopen("../tests/testFiles/pe32+-notepad++.exe", "rb");
    if(pefile == NULL){
        perror("Failed to open file.\n");
    }

    struct IMAGE_DOS_HEADER* msDOSHeader = malloc(sizeof(struct IMAGE_DOS_HEADER));

    parseMSDOSHeader(pefile, msDOSHeader);

    assert_int_equal(msDOSHeader->e_magic, 0x4d5a);
    assert_int_equal(msDOSHeader->e_cblp, 0x9000);
    assert_int_equal(msDOSHeader->e_cp, 0x300);
    assert_int_equal(msDOSHeader->e_crlc, 0x00);
    assert_int_equal(msDOSHeader->e_cparhdr, 0x400);
    assert_int_equal(msDOSHeader->e_minalloc, 0x00);
    assert_int_equal(msDOSHeader->e_maxalloc, 0xffff);
    assert_int_equal(msDOSHeader->e_ss, 0x00);
    assert_int_equal(msDOSHeader->e_sp, 0xb800);
    assert_int_equal(msDOSHeader->e_csum, 0x00);
    assert_int_equal(msDOSHeader->e_ip, 0x00);
    assert_int_equal(msDOSHeader->e_cs, 0x00);
    assert_int_equal(msDOSHeader->e_lfarlc, 0x4000);
    assert_int_equal(msDOSHeader->e_ovno, 0x00);
    assert_int_equal(msDOSHeader->e_oeminfo, 0x00);

    for(size_t i=0;i<4;i++){
        assert_int_equal(msDOSHeader->e_res[i], 0x00);
    }

    for(size_t i=0;i<10;i++){
        assert_int_equal(msDOSHeader->e_res2[i], 0x00);
    }

    assert_int_equal(msDOSHeader->e_lfanew, 0x18010000);

    free(msDOSHeader);
    fclose(pefile);
    (void) state;
}

void test_parseCoffHeader(void** state){

    FILE* pefile = fopen("../tests/testFiles/pe32+-notepad++.exe", "rb");
    if(pefile == NULL){
        perror("Failed to open file.\n");
    }

    struct IMAGE_COFF_HEADER* coffHeader = malloc(sizeof(struct IMAGE_COFF_HEADER));
    if(coffHeader == NULL){
        perror("Failed to allocate memory for COFFHEADER.\n");
    }

    coffHeader->machineArchitecture = malloc(31 * sizeof(char));
    if(coffHeader->machineArchitecture == NULL){
    	perror("Failed to allocate memory for coffHeader->machineArchitecture structure");
    	return;
    }
    
    memcpy(coffHeader->machineArchitecture, "INITIALIZATION_VALUE", 21);
    coffHeader->machineArchitecture[21] = '\0';

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
        (coffHeader->characteristicsList[i])[21] = '\0';
    }

    parseCoffHeader(pefile, convert_DWORD_To_uint32_t(0x18010000), coffHeader);
    
    assert_int_equal(coffHeader->peSignature, 0x50450000);
    assert_int_equal(coffHeader->machine, 0x6486);
    assert_int_equal(coffHeader->numberOfSections, 0x700);
    assert_int_equal(coffHeader->timeDateStamp, 0x1d7edb64);
    assert_int_equal(coffHeader->pointerToSymbolTable, 0x0000);
    assert_int_equal(coffHeader->numberOfSymbols, 0x0000);
    assert_int_equal(coffHeader->sizeOfOptionalHeader, 0xf000);
    assert_int_equal(coffHeader->characteristics, 0x2200);
   
    for(size_t i=0;i<17;i++){
        free(coffHeader->characteristicsList[i]);
    }

    free(coffHeader->machineArchitecture);
    free(coffHeader->characteristicsList);
    free(coffHeader);
    fclose(pefile);
    (void) state;
}

void test_parseSectionHeaders(void** state){
    FILE* pefile = fopen("../tests/testFiles/pe32+-notepad++.exe", "rb");
    if(pefile == NULL){
        perror("Failed to open file.\n");
    }
    
    uint16_t numberOfSections = 0x07;
    uint32_t memoryOffset = convert_DWORD_To_uint32_t(0x18010000) + 24 + convert_WORD_To_uint16_t(0xf000);
    struct SECTION_HEADER* sectionHeader = malloc(numberOfSections * sizeof(struct SECTION_HEADER));
    if(sectionHeader == NULL){
    	perror("Failed to allocate memory for sectionHeader structure\n");
    	return;
    }

    parseSectionHeaders(pefile, numberOfSections, memoryOffset, sectionHeader);

    assert_int_equal(sectionHeader[0].name, 0x2e74657874000000);
    assert_int_equal(sectionHeader[0].virtualSize, 0x48ad4200);
    assert_int_equal(sectionHeader[0].virtualAddress, 0x100000);
    assert_int_equal(sectionHeader[0].sizeOfRawData, 0xae4200);
    assert_int_equal(sectionHeader[0].pointerToRawData, 0x40000);
    assert_int_equal(sectionHeader[0].pointerToRelocations, 0x0000);
    assert_int_equal(sectionHeader[0].pointerToLineNumbers, 0x0000);
    assert_int_equal(sectionHeader[0].numberOfRelocations, 0x00);
    assert_int_equal(sectionHeader[0].numberOfLineNumbers, 0x00);
    assert_int_equal(sectionHeader[0].characteristics, 0x20000060);


    free(sectionHeader);
    fclose(pefile);
    (void) state;
}

void test_computeMD5Hash(void** state){
    
    FILE* pefile = fopen("../tests/testFiles/pe32+-notepad++.exe", "rb");
	if(pefile == NULL){
		perror("Failed to open file. Verify whether the file exists or not.\n");
	}

    char* md5HashValue = malloc(33 * sizeof(char));
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
    assert_string_equal(md5HashValue, "d07bed882cabe550a82cec0030d26226");
    
    free(md5HashValue);
    (void) state;
}

void test_computeSHA1Hash(void** state){

    FILE* pefile = fopen("../tests/testFiles/pe32+-notepad++.exe", "rb");
	if(pefile == NULL){
		perror("Failed to open file. Verify whether the file exists or not.\n");
	}

    char* sha1HashValue = malloc(41 * sizeof(char));

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
    assert_string_equal(sha1HashValue, "b67e9cdce640132a4b8961e5734ddb64d7cefdc5");
    
    free(sha1HashValue);
    (void) state;
}

void test_computeSHA256Hash(void** state){

    FILE* pefile = fopen("../tests/testFiles/pe32+-notepad++.exe", "rb");
	if(pefile == NULL){
		perror("Failed to open file. Verify whether the file exists or not.\n");
	}

    char* sha256HashValue = malloc(65 * sizeof(char));

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
    assert_string_equal(sha256HashValue, "674815647a6b7ccb1ea6747f3823db035d78d4237430bd102890703ba9cf7195");
    
    free(sha256HashValue);
    (void) state;
}

 