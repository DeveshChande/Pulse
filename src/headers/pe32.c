#include "pe32.h"

uint32_t convert_DWORD_To_uint32_t(DWORD structureValue){
    uint32_t convertedStructureValue = (((structureValue&255)&15)*16777216) + (((structureValue&255)>>4)*268435456) + ((((structureValue>>8)&255)&15)*65536) + ((((structureValue>>8)&255)>>4)*1048576) + (((structureValue>>16)&15)*256) + ((((structureValue>>16)&255)>>4)*4096) + (((structureValue>>24)&15)*1) + (((structureValue>>24)>>4)*16);
    return convertedStructureValue;
}

uint16_t convert_WORD_To_uint16_t(WORD structureValue){
    uint16_t convertedStructureValue = (uint16_t)((structureValue&15)*256 + ((structureValue>>4)&15)*4096 + (((structureValue>>8)&15)*1) + ((structureValue>>12)&15)*16);
    return convertedStructureValue;
}

unsigned char hexdigit2int(unsigned char xd){
  if (xd <= '9')
    return xd - '0';
  xd = (unsigned char) tolower(xd);
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
        const unsigned char high = hexdigit2int((unsigned char) *src++);
        const unsigned char low  = hexdigit2int((unsigned char) *src++);
        *dst++ = (char) ((high << 4) | low);
    }
    *dst = '\0';
    strcpy(computedString, text);
    free(text);
    return computedString;
}

void initializeOptionalHeader32(struct IMAGE_OPTIONAL_HEADER32* optionalHeader32){

    optionalHeader32->magic = (uint16_t)0;
    optionalHeader32->majorLinkerVersion = (uint8_t)0;
    optionalHeader32->minorLinkerVersion = (uint8_t)0;
    optionalHeader32->sizeOfCode = (uint32_t)0;
    optionalHeader32->sizeOfInitializedData = (uint32_t)0;
    optionalHeader32->sizeOfUninitializedData = (uint32_t)0;
    optionalHeader32->addressOfEntryPoint = (uint32_t)0;
    optionalHeader32->baseOfCode = (uint32_t)0;
    optionalHeader32->baseOfData = (uint32_t)0;
    optionalHeader32->imageBase = (uint32_t)0;
    optionalHeader32->sectionAlignment = (uint32_t)0;
    optionalHeader32->fileAlignment = (uint32_t)0;
    optionalHeader32->majorOperatingSystemVersion = (uint16_t)0;
    optionalHeader32->minorOperatingSystemVersion = (uint16_t)0;
    optionalHeader32->majorImageVersion = (uint16_t)0;
    optionalHeader32->minorImageVersion = (uint16_t)0;
    optionalHeader32->majorSubsystemVersion = (uint16_t)0;
    optionalHeader32->minorSubsystemVersion = (uint16_t)0;
    optionalHeader32->win32VersionValue = (uint32_t)0;
    optionalHeader32->sizeOfImage = (uint32_t)0;
    optionalHeader32->sizeOfHeaders = (uint32_t)0;
    optionalHeader32->checksum = (uint32_t)0;
    optionalHeader32->subsystem = (uint16_t)0;
    optionalHeader32->dllCharacteristics = (uint16_t)0;
    optionalHeader32->sizeOfStackReserve = (uint32_t)0;
    optionalHeader32->sizeOfStackCommit = (uint32_t)0;
    optionalHeader32->sizeOfHeapReserve = (uint32_t)0;
    optionalHeader32->sizeOfHeapCommit = (uint32_t)0;
    optionalHeader32->loaderFlags = (uint32_t)0;
    optionalHeader32->numberOfRvaAndSizes = (uint32_t)0;

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

    uint16_t imageFileCharacteristics[16] = {1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768};
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

void initializeExportDirectory32(struct IMAGE_EXPORT_DIRECTORY32* exports32){
    exports32->characteristics = (uint32_t)0;
    exports32->timeDateStamp = (uint32_t)0;
    exports32->majorVersion = (uint16_t)0;
    exports32->minorVersion = (uint16_t)0;
    exports32->name = (uint32_t)0;
    exports32->base = (uint32_t)0;
    exports32->numberOfFunctions = (uint32_t)0;
    exports32->numberOfNames = (uint32_t)0;
    exports32->addressOfFunctions = (uint32_t)0;
    exports32->addressOfNames = (uint32_t)0;
    exports32->addressOfOrdinals = (uint32_t)0;
}

void parseExports32(FILE* pefile, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER* sectionHeader32, struct IMAGE_EXPORT_DIRECTORY32* exports32, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses){
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

void exportsConsoleOutput32(FILE* pefile, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32, struct IMAGE_EXPORT_DIRECTORY32* exports32, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses, uint16_t numberOfSections, struct SECTION_HEADER* sectionHeader32){

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
        
        struct EXPORT_DATA_DIRECTORY* exportDirectory = malloc(sizeof(struct EXPORT_DATA_DIRECTORY));
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

void initializeImportDescriptor32(struct IMAGE_IMPORT_DESCRIPTOR32* importDescriptor){

        importDescriptor->u.OriginalFirstThunk.u1.ordinal = (uint32_t)0;
    	importDescriptor->timeDateStamp = (uint32_t)0;
    	importDescriptor->forwarderChain = (uint32_t)0;
    	importDescriptor->name = (uint32_t)0;
    	importDescriptor->FirstThunk.u1.addressOfData = (uint32_t)0;
}

void parseImports32(FILE* pefile, size_t numID, uint32_t diskOffset, struct IMAGE_IMPORT_DESCRIPTOR32** imports32){
    
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

void importsConsoleOutput32(FILE* pefile, size_t numID, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER* sectionHeader32, struct IMAGE_IMPORT_DESCRIPTOR32** imports32){

	uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
	uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
	
	printf("\n\nIMPORT INFORMATION\n-----------------------------------\n\n");
	
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

void initializeCertificate32(size_t certificateCount, struct IMAGE_CERTIFICATE32* certificate32){

    for(size_t i=0;i<certificateCount;i++){    
            certificate32[i].dwLength = (uint32_t)0;
            certificate32[i].wRevision = (uint16_t)0;
            certificate32[i].wCertificateType = (uint16_t)0;
    }
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

void certificateConsoleOutput32(size_t certificateCount, struct IMAGE_CERTIFICATE32* certificate32){
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

void initializeTLS32(struct IMAGE_TLS_DIRECTORY32* tls32){

    tls32->startAddressOfRawData = (uint32_t)0;
    tls32->endAddressOfRawData = (uint32_t)0;
    tls32->addressOfIndex = (uint32_t)0;
    tls32->addressOfCallBacks = (uint32_t)0;
    tls32->sizeOfZeroFill = (uint32_t)0;
    tls32->characteristics = (uint32_t)0;
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

void tlsConsoleOutput32(struct IMAGE_TLS_DIRECTORY32* tls32){

	    printf("TLS Information\n---------------------------------\n");
	    printf("tls32->startAddressOfRawData: %04x\n", tls32->startAddressOfRawData);
	    printf("tls32->endAddressOfRawData: %04x\n", tls32->endAddressOfRawData);
	    printf("tls32->addressOfIndex: %04x\n", tls32->addressOfIndex);
	    printf("tls32->addressOfCallBacks: %04x\n", tls32->addressOfCallBacks);
	    printf("tls32->sizeOfZeroFill: %04x\n", tls32->sizeOfZeroFill);
	    printf("tls32->characteristics: %04x\n\n\n", tls32->characteristics);

}

void initializeLoadConfig32(struct IMAGE_LOAD_CONFIG32* loadConfig32){

        loadConfig32->characteristics = (uint32_t)0;
    	loadConfig32->timeDateStamp = (uint32_t)0;
    	loadConfig32->majorVersion = (uint16_t)0;
    	loadConfig32->minorVersion = (uint16_t)0;
    	loadConfig32->globalFlagsClear = (uint32_t)0;
    	loadConfig32->globalFlagsSet = (uint32_t)0;
    	loadConfig32->criticalSectionDefaultTimeout = (uint32_t)0;
    	loadConfig32->deCommitFreeBlockThreshold = (uint32_t)0;
    	loadConfig32->deCommitTotalFreeThreshold = (uint32_t)0;
    	loadConfig32->lockPrefixTable = (uint32_t)0;
    	loadConfig32->maximumAllocationSize = (uint32_t)0;
    	loadConfig32->virtualMemoryThreshold = (uint32_t)0;
    	loadConfig32->processAffinityMask = (uint32_t)0;
    	loadConfig32->processHeapFlags = (uint32_t)0;
    	loadConfig32->cSDVersion = (uint16_t)0;
    	loadConfig32->reserved = (uint16_t)0;
    	loadConfig32->editList = (uint32_t)0;
    	loadConfig32->securityCookie = (uint32_t)0;
    	loadConfig32->sEHandlerTable = (uint32_t)0;
    	loadConfig32->sEHandlerCount = (uint32_t)0;
    	loadConfig32->guardCFCheckFunctionPointer = (uint32_t)0;
    	loadConfig32->guardCFDispatchFunctionPointer = (uint32_t)0;
    	loadConfig32->guardCFFunctionTable = (uint32_t)0;
    	loadConfig32->guardCFFunctionCount = (uint32_t)0;
    	loadConfig32->guardFlags = (uint32_t)0;
    	loadConfig32->codeIntegrity[0] = (uint32_t)0;
    	loadConfig32->codeIntegrity[1] = (uint32_t)0;
    	loadConfig32->codeIntegrity[2] = (uint32_t)0;
    	loadConfig32->guardAddressTakenIatEntryTable = (uint32_t)0;
    	loadConfig32->guardAddressTakenIatEntryCount = (uint32_t)0;
    	loadConfig32->guardLongJumpTargetTable = (uint32_t)0;
    	loadConfig32->guardLongJumpTargetCount = (uint32_t)0;
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

void loadConfigConsoleOutput32(struct IMAGE_LOAD_CONFIG32* loadConfig32){

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

void consoleOutput32(struct IMAGE_DOS_HEADER* msDOSHeader, struct IMAGE_COFF_HEADER* coffHeader, struct IMAGE_OPTIONAL_HEADER32* optionalHeader32, struct SECTION_HEADER* sectionHeader32){

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
    "msDOSHeader->e_oeminfo: 0x%02x\n"
    "msDOSHeader->e_res2: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
    "msDOSHeader->e_lfanew: 0x%04x\n\n"
    ,msDOSHeader->e_magic, msDOSHeader->e_cblp, msDOSHeader->e_cp, msDOSHeader->e_crlc
    ,msDOSHeader->e_cparhdr, msDOSHeader->e_minalloc, msDOSHeader->e_maxalloc, msDOSHeader->e_ss
    ,msDOSHeader->e_sp, msDOSHeader->e_csum, msDOSHeader->e_ip, msDOSHeader->e_cs
    ,msDOSHeader->e_lfarlc, msDOSHeader->e_ovno, msDOSHeader->e_oeminfo, msDOSHeader->e_res[0], msDOSHeader->e_res[1]
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
    ,reverse_endianess_uint32_t(coffHeader->pointerToSymbolTable), reverse_endianess_uint32_t(coffHeader->numberOfSymbols), reverse_endianess_uint16_t(coffHeader->sizeOfOptionalHeader)
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
    
    struct IMAGE_DOS_HEADER* msDOSHeader = malloc(sizeof(struct IMAGE_DOS_HEADER));
    if(msDOSHeader == NULL){
    	perror("Failed to allocate memory for msDOSHeader structure");
    	return;
    }
    
    initializeMSDOSHeader(msDOSHeader);
    
    struct IMAGE_COFF_HEADER* coffHeader = malloc(sizeof(struct IMAGE_COFF_HEADER));
    if(coffHeader == NULL){
    	perror("Failed to allocate memory for coffHeader structure");
    	return;
    }
    
    initializeCoffHeader(coffHeader);
    
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
    	
    struct IMAGE_OPTIONAL_HEADER32* optionalHeader32 = malloc(sizeof(struct IMAGE_OPTIONAL_HEADER32));
    if(optionalHeader32 == NULL){
    	perror("Failed to allocate memory for optionalHeader32 structure");
    	return;
    }
    initializeOptionalHeader32(optionalHeader32);
    
    optionalHeader32->subsystemType = malloc(41 * sizeof(char));
    if(optionalHeader32->subsystemType == NULL){
    	perror("Failed to allocate memory for optionalHeader32->subsystemType structure");
    	return;
    }
    memcpy(optionalHeader32->subsystemType, "SUBSYSTEM_INITIALIZATION_VALUE", 31);
    optionalHeader32->subsystemType[31] = '\0';
    
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
        (optionalHeader32->dllCharacteristicsList[i])[21] = '\0';
    }
    

    parseMSDOSHeader(pefile, msDOSHeader);
    parseCoffHeader(pefile, convert_DWORD_To_uint32_t(msDOSHeader->e_lfanew), coffHeader);
    parseOptionalHeader32(pefile, convert_DWORD_To_uint32_t(msDOSHeader->e_lfanew), optionalHeader32);
    
    uint16_t numberOfSections = convert_WORD_To_uint16_t(coffHeader->numberOfSections);
    uint32_t memoryOffset = convert_DWORD_To_uint32_t(msDOSHeader->e_lfanew) + 24 + convert_WORD_To_uint16_t(coffHeader->sizeOfOptionalHeader);
    struct SECTION_HEADER* sectionHeader32 = malloc(numberOfSections * sizeof(struct SECTION_HEADER));

    if(sectionHeader32 == NULL){
    	perror("Failed to allocate memory for sectionHeader32 structure\n");
    	return;
    }
    initializeSectionHeader(numberOfSections, sectionHeader32);
    
    
    parseSectionHeaders(pefile, numberOfSections, memoryOffset, sectionHeader32);
    
    if(!psList->exportResult){
    	consoleOutput32(msDOSHeader, coffHeader, optionalHeader32, sectionHeader32);
    
    if(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[0].virtualAddress) != 0){
    	struct IMAGE_EXPORT_DIRECTORY32* exports32 = malloc(sizeof(struct IMAGE_EXPORT_DIRECTORY32));
        if(exports32 == NULL){
    	    printf("Failed to allocate memory for exports32 structure\n");
    	    return;
        }
        initializeExportDirectory32(exports32);
        
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
    		initializeImportDescriptor32(imports32[i]);	
    	}
    	
    	parseImports32(pefile, numID, diskOffset, imports32);
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
    
        struct IMAGE_EXCEPTION tmpexception32;
        
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
    
    
    	struct IMAGE_EXCEPTION* exception32 = malloc(exceptionCount * sizeof(struct IMAGE_EXCEPTION));
    	if(exception32 == NULL){
    	    perror("Failed to allocate memory for exception32");
    	    return;
    	
    	}
    	
    	initializeException(exceptionCount, exception32);
    	parseException(pefile, diskOffset, exceptionCount, exception32);
    	exceptionConsoleOutput(exceptionCount, exception32);
    	
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
        if(certificate32 == NULL){
            perror("Failed to allocate memory for certificate32");
            return;
        }
        initializeCertificate32(certificateCount, certificate32);
        parseCertificate32(pefile, diskOffset, certificateCount, certificate32, optionalHeader32);
        certificateConsoleOutput32(certificateCount, certificate32);
        free(certificate32);
    
    }
    
    if(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[5].virtualAddress) != 0){
	   struct IMAGE_BASE_RELOCATION* baseReloc32 = malloc(sizeof(struct IMAGE_BASE_RELOCATION));
	   if(baseReloc32 == NULL){
		     perror("Failed to allocate memory for baseReloc32");
		     return;
	   }
	   initializeBaseReloc(1, baseReloc32);
	   
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[5].virtualAddress), numberOfSections, sectionHeader32);
    	uint32_t tmpDiskOffset = diskOffset;
    	
    	baseReloc32->pageRVA = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset, DWORD_Buffer));
     	baseReloc32->blockSize = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer));
     	
     	tmpDiskOffset += 8;
     	size_t baseRelocCount = 0;
    	uint32_t typeCount = 0;
    	
    	while((baseReloc32->pageRVA != 0) && (baseReloc32->blockSize != 0)){
    		baseRelocCount++;
        	typeCount = (baseReloc32->blockSize - 8) / 2;
        	
        	tmpDiskOffset += typeCount * 2;

        	baseReloc32->pageRVA = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset, DWORD_Buffer));
        	baseReloc32->blockSize = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer));
        	tmpDiskOffset += 8;
    	}
    	
    	free(baseReloc32);
    	baseReloc32 = malloc(baseRelocCount * sizeof(struct IMAGE_BASE_RELOCATION));
	initializeBaseReloc(baseRelocCount, baseReloc32);
    	parseBaseReloc(pefile, diskOffset, baseRelocCount, baseReloc32);
    	baseRelocConsoleOutput(pefile, diskOffset, baseRelocCount, baseReloc32);
    	free(baseReloc32);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[6].virtualAddress) != 0){
    	size_t debugCount = reverse_endianess_uint32_t(optionalHeader32->dataDirectory[6].size / sizeof(struct IMAGE_DEBUG_DIRECTORY));
    	struct IMAGE_DEBUG_DIRECTORY* debug32 = malloc(debugCount * sizeof(struct IMAGE_DEBUG_DIRECTORY));
    	if(debug32 == NULL){
    		perror("Failed to allocate memory for debug32");
    		return;
    	}
    	initializeDebug(debugCount, debug32);
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[6].virtualAddress), numberOfSections, sectionHeader32);
    	
    	parseDebug(pefile, debugCount, diskOffset, debug32);
    	debugConsoleOutput(pefile, debugCount, debug32, sectionHeader32);
    	free(debug32);
    
    }
    
    if(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[9].virtualAddress) != 0){
    	struct IMAGE_TLS_DIRECTORY32* tls32 = malloc(sizeof(struct IMAGE_TLS_DIRECTORY32));
    	if(tls32 == NULL){
    	    perror("Failed to allocate memory for tls32");
    	    return;
    	}
    	initializeTLS32(tls32);
    	
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
    	initializeLoadConfig32(loadConfig32);
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[10].virtualAddress), numberOfSections, sectionHeader32);
    	
    	parseLoadConfig32(pefile, diskOffset, loadConfig32);
    	loadConfigConsoleOutput32(loadConfig32);
    	free(loadConfig32);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[11].virtualAddress) != 0){
    	struct IMAGE_BOUND_IMPORT_DESCRIPTOR tmpBounds32;
    	uint32_t tmpDiskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[11].virtualAddress), numberOfSections, sectionHeader32);
    	uint32_t boundsCount = 0;
    	
    	tmpBounds32.timestamp = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    	tmpBounds32.offsetModuleName = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
    	tmpBounds32.numberOfModuleForwarderRefs = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
    	boundsCount++;
    	tmpDiskOffset += 8;
    	
    	while((tmpBounds32.timestamp != 0) && (tmpBounds32.offsetModuleName != 0) && (tmpBounds32.numberOfModuleForwarderRefs != 0)){
    		
    		if(tmpBounds32.numberOfModuleForwarderRefs != 0){
    			struct IMAGE_BOUND_FORWARDER_REF tmpForwards32;
                tmpForwards32.timestamp  = 1;
                tmpForwards32.offsetModuleName = 1;
                tmpForwards32.reserved = 1;

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
    	
    	struct IMAGE_BOUND_IMPORT_DESCRIPTOR* bounds32 = malloc(boundsCount * sizeof(struct IMAGE_BOUND_IMPORT_DESCRIPTOR));
    	if(bounds32 == NULL){
    		perror("Failed to allocate memory for bounds32");
    		return;
    	}
    	initializeBoundImport(boundsCount, bounds32);
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader32->dataDirectory[11].virtualAddress), numberOfSections, sectionHeader32);
    	parseBoundImport(pefile, diskOffset, boundsCount, bounds32);
    	boundsConsoleOutput(boundsCount, bounds32);
    	
    	free(bounds32);
    }
    
    if(psList->computeHash){
        char* md5HashValue = malloc(33 * sizeof(char));
        if(md5HashValue == NULL){
        	perror("Unable to allocate memory for md5HashValue");
        }
        char* sha1HashValue = malloc(41 * sizeof(char));
        if(sha1HashValue == NULL){
        	perror("Unable to allocate memory for sha1HashValue");
        }
        char* sha256HashValue = malloc(65 * sizeof(char));
        if(sha256HashValue == NULL){
        	perror("Unable to allocate memory for sha256HashValue");
        }
        printf("\n\nHASHES\n---------------\n");
    	md5HashValue = computeMD5Hash(pefile, md5HashValue);
    	printf("MD5: %s\n", md5HashValue);
    	sha1HashValue = computeSHA1Hash(pefile, sha1HashValue);
    	printf("SHA1: %s\n", sha1HashValue);
    	sha256HashValue = computeSHA256Hash(pefile, sha256HashValue);
    	printf("SHA256: %s\n", sha256HashValue);
    	free(md5HashValue);
    	free(sha1HashValue);
    	free(sha256HashValue);
    }
    
    if(psList->vtLookup){
        char* sha256HashValue = malloc(65 * sizeof(char));
        if(sha256HashValue == NULL){
        	perror("Unable to allocate memory for sha256HashValue in vtLookup");
        }
        sha256HashValue = computeSHA256Hash(pefile, sha256HashValue);
    	virusTotalResults(sha256HashValue, psList->vtAPIKey);
    	free(sha256HashValue);
    }
    	
    
    for(size_t i=0;i<17;i++){
        free(coffHeader->characteristicsList[i]);
    }
    	
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
