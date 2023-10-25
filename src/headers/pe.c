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

}

void parseMSDOSHeader(FILE* pefile, struct IMAGE_DOS_HEADER* msDOSHeader){
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