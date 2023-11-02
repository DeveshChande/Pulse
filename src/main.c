#include <getopt.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../src/headers/pe.c"
#include "../src/headers/pe32.c"
#include "../src/headers/pe64.c"
#include "../tests/test_fileOperations.c"
#include "../tests/test_pe.c"

#define OPTSTR "-:"

int main(int argc, char* argv[]){

    #ifdef DEBUG
    const struct CMUnitTest tests[] = {
    	cmocka_unit_test(test_reverse_endianess_uint8_t),
    	cmocka_unit_test(test_reverse_endianess_uint16_t),
    	cmocka_unit_test(test_reverse_endianess_uint32_t),
    	cmocka_unit_test(test_reverse_endianess_uint64_t),
        cmocka_unit_test(test_readByte),
        cmocka_unit_test(test_readWord),
        cmocka_unit_test(test_readDWord),
        cmocka_unit_test(test_readQWord),
        cmocka_unit_test(test_convert_WORD_To_uint16_t),
        cmocka_unit_test(test_convert_DWORD_To_uint32_t),
        cmocka_unit_test(test_hexdigit2int),
        cmocka_unit_test(test_convert_uint64_t_ToString),
        cmocka_unit_test(test_convertRelativeAddressToDiskOffset),
        cmocka_unit_test(test_initializeMSDOSHeader),
        cmocka_unit_test(test_initializeCoffHeader),
        cmocka_unit_test(test_initializeSectionHeader),
        cmocka_unit_test(test_initializeException),
        cmocka_unit_test(test_initializeBaseReloc),
        cmocka_unit_test(test_initializeDebug),
        cmocka_unit_test(test_computeMD5Hash),
        cmocka_unit_test(test_computeSHA1Hash),
        cmocka_unit_test(test_computeSHA256Hash)
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
    #endif
    
    int opt_index = 0;
    int opt = 0;
    static int f_exportResult = 0;
    static int f_extractResources = 0;
    static int f_extractStrings = 0;
    static int f_urlLookup = 0;
    static int f_shodanLookup = 0;
    static int f_dnsLookup = 0;
    static int f_computeHash = 0;
    static int f_capabilityDetection = 0;
    static struct option long_options[] = {
        {"file", optional_argument, NULL, 0},
        {"directory", optional_argument, NULL, 0},
        {"exportResult", no_argument, &f_exportResult, 1},
        {"extractStrings", no_argument, &f_extractStrings, 1},
        {"vtLookup", required_argument, NULL, 0},
        {"urlLookup", no_argument, &f_urlLookup, 1},
        {"shodanLookup", no_argument, &f_shodanLookup, 1},
        {"computeHash", no_argument, &f_computeHash, 1},
        {"capabilityDetection", no_argument, &f_capabilityDetection, 1},
        {NULL, 0, NULL, 0}
    };

    if(argc == 1){
        fprintf(stderr, "ERROR: Please enter the appropriate command-line options.\n");
    }
    clock_t t = clock();
    struct switchList* psList = malloc(sizeof(struct switchList));
    
    if(psList != NULL){
    	psList->fileSpecified = true;
    	psList->pathOfFileSpecified = "";
    	psList->directorySpecified = true;
    	psList->pathOfDirectorySpecified = "";
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
    	fprintf(stderr, "Failed %s in file %s at line #%d\n", __FUNCTION__, __FILE__, __LINE__);
    	exit(EXIT_FAILURE);
    }
    
    
    
    while((opt = getopt_long(argc, argv, OPTSTR, long_options, &opt_index)) != -1){
        switch(opt){
            case 0:
                if(!strcmp(long_options[opt_index].name, "file")){
                    psList->fileSpecified = true;
                    psList->pathOfFileSpecified = optarg;
                }
                else if(!strcmp(long_options[opt_index].name, "directory")){
                    psList->directorySpecified = true;
                    psList->pathOfDirectorySpecified = optarg;
                }
                else if(f_exportResult){
                    psList->exportResult = true;
                }
                else if(f_extractResources){
                    psList->extractResources = true;
                }
                else if(f_extractStrings){
                    psList->extractStrings = true;
                }
                else if(!strcmp(long_options[opt_index].name, "vtLookup")){
                    psList->vtLookup = true;
                    psList->vtAPIKey = optarg;
                }
                else if(f_urlLookup){
                    psList->urlLookup = true;
                }
                else if(f_shodanLookup){
                    psList->shodanLookup = true;
                }
                else if(f_dnsLookup){
                    psList->dnsLookup = true;
                }
                else if(f_computeHash){
                    psList->computeHash = true;
                }
                else if(f_capabilityDetection){
                    psList->capabilityDetection = true;
                }
                else{
                    ;
                }
                break;
            case 1:
                printf("Regular argument: %s\n", optarg);
                break;
            case '?':
                printf("Unknown option: %s\n", argv[optind-1]);
                break;
            case ':':
                printf("Missing argument for %s\n", optarg);
                break;
            default:
                printf("?? getopt returned character code 0%o ??\n", opt);
                break;
        }
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
                printf("Error: Unsupported image type.\n\n");
                break;
        }

        free(WORD_Buffer);
        free(DWORD_Buffer);
    }  
    else{
        fprintf(stderr, "Error: Failed call to fopen(\"%s\", \"rb\") from %s at line #%d\n", psList->pathOfFileSpecified, __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }
    
    fclose(pefile);
    free(psList); 

    t = clock() - t;
    double time_taken = ((double)t)/CLOCKS_PER_SEC;
    printf("\n\nParsing took %f seconds to execute.\n", time_taken);
    
    (void) argc;
    (void) argv;

    exit(EXIT_SUCCESS);
}
