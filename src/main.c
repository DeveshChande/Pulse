#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <headers/pe32.h>
#include <headers/pe64.h>

int main(int argc, char* argv[]){
    clock_t t = clock();
    struct switchList* psList = malloc(sizeof(struct switchList));
    
    if(psList != NULL){
    	psList->fileSpecified = true;
    	psList->pathOfFileSpecified = "/test/samples/ChromeSetup.exe";
    	psList->directorySpecified = true;
    	psList->pathOfDirectorySpecified = "/test/samples/";
    	psList->exportResult = false;
    	psList->extractResources = false;
    	psList->extractStrings = false;
    	psList->vtLookup = false;
    	psList->urlLookup = false;
    	psList->shodanLookup = false;
    	psList->dnsLookup = false;
    	psList->computeHash = false;
    	psList->capabilityDetection = false;
    }
    else{
    	perror("Failed to allocate memory for switchList");
    	return -1;
    }
    

    size_t argCount = 0;
    for(argCount=1; argCount<argc; argCount++){
        if(!strcmp(argv[argCount], "--path")){
            psList->fileSpecified = true;
            psList->pathOfFileSpecified = argv[argCount+1];
            argCount++;
        }

        if(!strcmp(argv[argCount], "--directory")){
            psList->directorySpecified = true;
            psList->pathOfDirectorySpecified = argv[argCount+1];
            argCount++;
        }
        
        if(!strcmp(argv[argCount], "--exportResult"))
            psList->exportResult = true;

        if(!strcmp(argv[argCount], "--extractResources"))
            psList->extractResources = true;

        if(!strcmp(argv[argCount], "--extractStrings"))
            psList->extractStrings = true;

        if(!strcmp(argv[argCount], "--vtLookup"))
            psList->vtLookup = true;

        if(!strcmp(argv[argCount], "--urlLookup"))
            psList->urlLookup = true;

        if(!strcmp(argv[argCount], "--shodanLookup"))
            psList->shodanLookup = true;

        if(!strcmp(argv[argCount], "--dnsLookup"))
            psList->dnsLookup = true;

        if(!strcmp(argv[argCount], "--computeHash"))
            psList->computeHash = true;

        if(!strcmp(argv[argCount], "--capabilityDetection"))
            psList->capabilityDetection = true;
    }
    
 
    if(!psList->fileSpecified){
    	perror("No file specified. Terminating.\n");
    	return -1;
    }
    	
    
    FILE* pefile = fopen(psList->pathOfFileSpecified, "rb");
    
    if(pefile != NULL){
        uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
        uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
        uint32_t elfanew = convert_DWORD_To_uint32_t(readDWord(pefile, 0x3C, DWORD_Buffer));
        uint16_t trueMagic = reverse_endianess_uint16_t(readWord(pefile, elfanew+24, WORD_Buffer));

        switch(trueMagic){
            case 0x10b:
                parsePE32(pefile, psList);
                break;
            case 0x20b:
                parsePE64(pefile, psList);
                break;
            default:
                printf("ERROR: Unsupported type of image.\n\n");
                break;
        }

        free(WORD_Buffer);
        free(DWORD_Buffer);
    }  
    else{
        perror("Failed call to fopen()");
        return -1;
    }
    
    fclose(pefile);
    free(psList);
    
    t = clock() - t;
    double time_taken = ((double)t)/CLOCKS_PER_SEC;
    printf("\n\nParsing took %f seconds to execute.\n", time_taken);

    return 0;
}
