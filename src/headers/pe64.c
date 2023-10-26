#include "pe64.h"

uint64_t convertRelativeAddressToDiskOffset64_t(uint64_t relativeAddress, uint16_t numberOfSections,  struct SECTION_HEADER* sectionHeader64){

size_t i=0;

    for(i=0; i<numberOfSections; i++){
        uint64_t sectionHeaderVirtualAddress = (((sectionHeader64[i].virtualAddress&255)&15)*16777216) + (((sectionHeader64[i].virtualAddress&255)>>4)*268435456) + ((((sectionHeader64[i].virtualAddress>>8)&255)&15)*65536) + ((((sectionHeader64[i].virtualAddress>>8)&255)>>4)*1048576) + (((sectionHeader64[i].virtualAddress>>16)&15)*256) + ((((sectionHeader64[i].virtualAddress>>16)&255)>>4)*4096) + (((sectionHeader64[i].virtualAddress>>24)&15)*1) + (((sectionHeader64[i].virtualAddress>>24)>>4)*16);
        uint64_t sectionHeaderPointerToRawData = (((sectionHeader64[i].pointerToRawData&255)&15)*16777216) + (((sectionHeader64[i].pointerToRawData&255)>>4)*268435456) + ((((sectionHeader64[i].pointerToRawData>>8)&255)&15)*65536) + ((((sectionHeader64[i].pointerToRawData>>8)&255)>>4)*1048576) + (((sectionHeader64[i].pointerToRawData>>16)&15)*256) + ((((sectionHeader64[i].pointerToRawData>>16)&255)>>4)*4096) + (((sectionHeader64[i].pointerToRawData>>24)&15)*1) + (((sectionHeader64[i].pointerToRawData>>24)>>4)*16);
        uint64_t sectionHeaderSizeOfRawData = (((sectionHeader64[i].sizeOfRawData&255)&15)*16777216) + (((sectionHeader64[i].sizeOfRawData&255)>>4)*268435456) + ((((sectionHeader64[i].sizeOfRawData>>8)&255)&15)*65536) + ((((sectionHeader64[i].sizeOfRawData>>8)&255)>>4)*1048576) + (((sectionHeader64[i].sizeOfRawData>>16)&15)*256) + ((((sectionHeader64[i].sizeOfRawData>>16)&255)>>4)*4096) + (((sectionHeader64[i].sizeOfRawData>>24)&15)*1) + (((sectionHeader64[i].sizeOfRawData>>24)>>4)*16);
        
        if((relativeAddress >= sectionHeaderVirtualAddress) && (relativeAddress <= (sectionHeaderVirtualAddress + sectionHeaderSizeOfRawData))){
            return (uint64_t)(sectionHeaderPointerToRawData + relativeAddress - sectionHeaderVirtualAddress);
        }
    }

    return 0;

}

void initializeOptionalHeader64(struct IMAGE_OPTIONAL_HEADER64* optionalHeader64){

    optionalHeader64->magic = (uint16_t)0;
    optionalHeader64->majorLinkerVersion = (uint8_t)0;
    optionalHeader64->minorLinkerVersion = (uint8_t)0;
    optionalHeader64->sizeOfCode = (uint32_t)0;
    optionalHeader64->sizeOfInitializedData = (uint32_t)0;
    optionalHeader64->sizeOfUninitializedData = (uint32_t)0;
    optionalHeader64->addressOfEntryPoint = (uint32_t)0;
    optionalHeader64->baseOfCode = (uint32_t)0;

    optionalHeader64->imageBase = (uint64_t)0;
    optionalHeader64->sectionAlignment = (uint64_t)0;
    optionalHeader64->fileAlignment = (uint64_t)0;
    optionalHeader64->majorOperatingSystemVersion = (uint16_t)0;
    optionalHeader64->minorOperatingSystemVersion = (uint16_t)0;
    optionalHeader64->majorImageVersion = (uint16_t)0;
    optionalHeader64->minorImageVersion = (uint16_t)0;
    optionalHeader64->majorSubsystemVersion = (uint16_t)0;
    optionalHeader64->minorSubsystemVersion = (uint16_t)0;
    optionalHeader64->win32VersionValue = (uint32_t)0;
    optionalHeader64->sizeOfImage = (uint32_t)0;
    optionalHeader64->sizeOfHeaders = (uint32_t)0;
    optionalHeader64->checksum = (uint32_t)0;
    optionalHeader64->subsystem = (uint16_t)0;
    optionalHeader64->dllCharacteristics = (uint16_t)0;
    optionalHeader64->sizeOfStackReserve = (uint64_t)0;
    optionalHeader64->sizeOfStackCommit = (uint64_t)0;
    optionalHeader64->sizeOfHeapReserve = (uint64_t)0;
    optionalHeader64->sizeOfHeapCommit = (uint64_t)0;
    optionalHeader64->loaderFlags = (uint32_t)0;
    optionalHeader64->numberOfRvaAndSizes = (uint32_t)0;

}

void parseOptionalHeader64(FILE* pefile, uint32_t elfanew, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64){
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));

    optionalHeader64->magic = readWord(pefile, elfanew+24, WORD_Buffer);
    optionalHeader64->majorLinkerVersion = readByte(pefile, elfanew+26, BYTE_Buffer);
    optionalHeader64->minorLinkerVersion = readByte(pefile, elfanew+27, BYTE_Buffer);
    optionalHeader64->sizeOfCode = readDWord(pefile, elfanew+28, DWORD_Buffer);
    optionalHeader64->sizeOfInitializedData = readDWord(pefile, elfanew+32, DWORD_Buffer);
    optionalHeader64->sizeOfUninitializedData = readDWord(pefile, elfanew+36, DWORD_Buffer);
    optionalHeader64->addressOfEntryPoint = readDWord(pefile, elfanew+40, DWORD_Buffer);
    optionalHeader64->baseOfCode = readDWord(pefile, elfanew+44, DWORD_Buffer);
    optionalHeader64->imageBase = readQWord(pefile, elfanew+48, QWORD_Buffer);
    optionalHeader64->sectionAlignment = readDWord(pefile, elfanew+56, DWORD_Buffer);
    optionalHeader64->fileAlignment = readDWord(pefile, elfanew+60, DWORD_Buffer);
    optionalHeader64->majorOperatingSystemVersion = readWord(pefile, elfanew+64, WORD_Buffer);
    optionalHeader64->minorOperatingSystemVersion = readWord(pefile, elfanew+66, WORD_Buffer);
    optionalHeader64->majorImageVersion = readWord(pefile, elfanew+68, WORD_Buffer);
    optionalHeader64->minorImageVersion = readWord(pefile, elfanew+70, WORD_Buffer);
    optionalHeader64->majorSubsystemVersion = readWord(pefile, elfanew+72, WORD_Buffer);
    optionalHeader64->minorSubsystemVersion = readWord(pefile, elfanew+74, WORD_Buffer);
    optionalHeader64->win32VersionValue = readDWord(pefile, elfanew+76, DWORD_Buffer);
    optionalHeader64->sizeOfImage = readDWord(pefile, elfanew+80, DWORD_Buffer);
    optionalHeader64->sizeOfHeaders = readDWord(pefile, elfanew+84, DWORD_Buffer);
    optionalHeader64->checksum = readDWord(pefile, elfanew+88, DWORD_Buffer);
    optionalHeader64->subsystem = readWord(pefile, elfanew+92, WORD_Buffer);
    optionalHeader64->dllCharacteristics = readWord(pefile, elfanew+94, WORD_Buffer);
    
    optionalHeader64->sizeOfStackReserve = readQWord(pefile, elfanew+96, QWORD_Buffer);
    optionalHeader64->sizeOfStackCommit = readQWord(pefile, elfanew+104, QWORD_Buffer);
    optionalHeader64->sizeOfHeapReserve = readQWord(pefile, elfanew+112, QWORD_Buffer);
    optionalHeader64->sizeOfHeapCommit = readQWord(pefile, elfanew+120, QWORD_Buffer);
    optionalHeader64->loaderFlags = readDWord(pefile, elfanew+128, DWORD_Buffer);
    optionalHeader64->numberOfRvaAndSizes = readDWord(pefile, elfanew+132, DWORD_Buffer);

    size_t j=0;
    size_t maxDirectories = reverse_endianess_uint32_t(optionalHeader64->numberOfRvaAndSizes);
    for(size_t i=0;i<maxDirectories;i++){
        optionalHeader64->dataDirectory[i].virtualAddress = readDWord(pefile, elfanew+136+j, DWORD_Buffer);
        j+=4;
        optionalHeader64->dataDirectory[i].size = readDWord(pefile, elfanew+136+j, DWORD_Buffer);
        j+=4;
    }

    switch(reverse_endianess_uint16_t(optionalHeader64->subsystem)){
        case 0:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_UNKNOWN", 24);
            break;
        case 1:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_NATIVE", 23);
            break;
        case 2:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_WINDOWS_GUI", 28);
            break;
        case 3:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_WINDOWS_CUI", 28);
            break;
        case 5:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_OS2_CUI", 24);
            break;
        case 7:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_POSIX_CUI", 26);
            break;
        case 8:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_NATIVE_WINDOWS", 31);
            break;
        case 9:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", 31);
            break;
        case 10:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_EFI_APPLICATION", 32);
            break;
        case 11:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", 40);
            break;
        case 12:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", 35);
            break;
        case 13:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_EFI_ROM", 24);
            break;
        case 14:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_XBOX", 21);
            break;
        case 16:
            memcpy(optionalHeader64->subsystemType, "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", 41);
            break;
        default:
            memcpy(optionalHeader64->subsystemType, "UNDEFINED_IMAGE_SUBSYSTEM_ANOMALY", 34);
            break;
    }

    uint16_t imageFileCharacteristics[16] = {1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768};
    int* savedCharacteristics = calloc(16, sizeof(int));
    j=0;
    uint16_t dllCharacteristics = reverse_endianess_uint16_t(optionalHeader64->dllCharacteristics);

    for(int i=15;i>=0;i--){
        if(((dllCharacteristics - imageFileCharacteristics[i]) >= 0) && (dllCharacteristics!=0)){
            savedCharacteristics[j++] = imageFileCharacteristics[i];
            dllCharacteristics -= imageFileCharacteristics[i];
        }
    }

    for(size_t i=0;i<j;i++){
        switch(savedCharacteristics[i]){
            case 32:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", 41);
                break;
            case 64:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", 38);
                break;
            case 128:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", 41);
                break;
            case 256:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_NX_COMPAT", 35);
                break;
            case 512:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", 38);
                break;
            case 1024:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_NO_SEH", 32);
                break;
            case 2048:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_NO_BIND", 33);
                break;
            case 4096:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_APPCONTAINER", 38);
                break;
            case 8192:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", 36);
                break;
            case 16384:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_GUARD_CF", 34);
                break;
            case 32768:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", 47);
                break;
            default:
                memcpy(optionalHeader64->dllCharacteristicsList[i], "UNKNOWN_DLL_CHARACTERISTICS_ANOMALY", 36);
                break;
        }
    }

    free(savedCharacteristics);
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);
}

void initializeExportDirectory64(struct IMAGE_EXPORT_DIRECTORY64* exports64){
    exports64->characteristics = (uint32_t)0;
    exports64->timeDateStamp = (uint32_t)0;
    exports64->majorVersion = (uint16_t)0;
    exports64->minorVersion = (uint16_t)0;
    exports64->name = (uint32_t)0;
    exports64->base = (uint32_t)0;
    exports64->numberOfFunctions = (uint32_t)0;
    exports64->numberOfNames = (uint32_t)0;
    exports64->addressOfFunctions = (uint32_t)0;
    exports64->addressOfNames = (uint32_t)0;
    exports64->addressOfOrdinals = (uint32_t)0;
}

void parseExports64(FILE* pefile, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER* sectionHeader64, struct IMAGE_EXPORT_DIRECTORY64* exports64, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses){
    uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));
    
    
    exports64->characteristics = readDWord(pefile, diskOffset, DWORD_Buffer);
    exports64->timeDateStamp = readDWord(pefile, diskOffset+4, DWORD_Buffer);
    exports64->majorVersion = readWord(pefile, diskOffset+8, WORD_Buffer);
    exports64->minorVersion = readWord(pefile, diskOffset+10, WORD_Buffer);
    exports64->name = readDWord(pefile, diskOffset+12, DWORD_Buffer);
    exports64->base = readDWord(pefile, diskOffset+16, DWORD_Buffer);
    exports64->numberOfFunctions = readDWord(pefile, diskOffset+20, DWORD_Buffer);
    exports64->numberOfNames = readDWord(pefile, diskOffset+24, DWORD_Buffer);
    exports64->addressOfFunctions = readDWord(pefile, diskOffset+28, DWORD_Buffer);
    exports64->addressOfNames = readDWord(pefile, diskOffset+32, DWORD_Buffer);
    exports64->addressOfOrdinals = readDWord(pefile, diskOffset+36, DWORD_Buffer);
    
    uint32_t functionsOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(exports64->addressOfFunctions), numberOfSections, sectionHeader64);
    
    for(size_t i=0;i<reverse_endianess_uint32_t(exports64->numberOfFunctions);i++)
    	exportFunctionAddresses[i] = reverse_endianess_uint32_t(readDWord(pefile, functionsOffset+i*sizeof(uint32_t), DWORD_Buffer));
    
    
    uint32_t namesOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(exports64->addressOfNames), numberOfSections, sectionHeader64);
    
    for(size_t i=0;i<reverse_endianess_uint32_t(exports64->numberOfNames);i++)
    	exportFunctionNames[i] = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(readDWord(pefile, namesOffset+i*sizeof(uint32_t), DWORD_Buffer)), numberOfSections, sectionHeader64);
    
    uint32_t ordinalsOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(exports64->addressOfOrdinals), numberOfSections, sectionHeader64);
    
    for(size_t i=0;i<reverse_endianess_uint32_t(exports64->numberOfNames);i++)
    	exportOrdinalAddresses[i] = reverse_endianess_uint16_t(readWord(pefile, ordinalsOffset+i*sizeof(uint16_t), WORD_Buffer));
    	
    free(BYTE_Buffer);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);

}

void exportsConsoleOutput64(FILE* pefile, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64, struct IMAGE_EXPORT_DIRECTORY64* exports64, uint32_t* exportFunctionAddresses, uint32_t* exportFunctionNames, uint16_t* exportOrdinalAddresses, uint16_t numberOfSections, struct SECTION_HEADER* sectionHeader64){

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
        ,reverse_endianess_uint32_t(exports64->characteristics), reverse_endianess_uint32_t(exports64->timeDateStamp), reverse_endianess_uint16_t(exports64->majorVersion), reverse_endianess_uint16_t(exports64->minorVersion),
        reverse_endianess_uint32_t(exports64->name), reverse_endianess_uint32_t(exports64->base), reverse_endianess_uint32_t(exports64->numberOfFunctions), reverse_endianess_uint32_t(exports64->numberOfNames),
        reverse_endianess_uint32_t(exports64->addressOfFunctions), reverse_endianess_uint32_t(exports64->addressOfNames), reverse_endianess_uint32_t(exports64->addressOfOrdinals));
    
    	printf("\t[RVA] : Exported Function\n\t-------------------------\n");
    	for(uint32_t i=0;i<reverse_endianess_uint32_t(exports64->numberOfNames);i++){
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
        exportDirectory->virtualAddress = reverse_endianess_uint32_t(optionalHeader64->dataDirectory[0].virtualAddress);
        exportDirectory->size = reverse_endianess_uint32_t(optionalHeader64->dataDirectory[0].size);
        
        for(size_t i=0; i<reverse_endianess_uint32_t(exports64->numberOfFunctions);i++){
        
            
            if((exportDirectory->virtualAddress < exportFunctionAddresses[i]) && (exportFunctionAddresses[i] < (exportDirectory->virtualAddress + exportDirectory->size))){
                uint32_t forwardedFunctionNameRVA = convertRelativeAddressToDiskOffset(exportFunctionAddresses[i], numberOfSections, sectionHeader64);
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

void initializeImportDescriptor64(struct IMAGE_IMPORT_DESCRIPTOR64* importDescriptor){

        importDescriptor->u.OriginalFirstThunk.u1.ordinal = (uint32_t)0;
    	importDescriptor->timeDateStamp = (uint32_t)0;
    	importDescriptor->forwarderChain = (uint32_t)0;
    	importDescriptor->name = (uint32_t)0;
    	importDescriptor->FirstThunk.u1.addressOfData = (uint32_t)0;
}

void parseImports64(FILE* pefile, size_t numID, uint32_t diskOffset, struct IMAGE_IMPORT_DESCRIPTOR64** imports64){
    
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));

    for(size_t i=0;i<numID;i++){
    	imports64[i]->u.OriginalFirstThunk.u1.ordinal = readDWord(pefile, diskOffset, DWORD_Buffer);
    	imports64[i]->timeDateStamp = readDWord(pefile, diskOffset+4, DWORD_Buffer);
    	imports64[i]->forwarderChain = readDWord(pefile, diskOffset+8, DWORD_Buffer);
    	imports64[i]->name = readDWord(pefile, diskOffset+12, DWORD_Buffer);
    	imports64[i]->FirstThunk.u1.addressOfData = readDWord(pefile, diskOffset+16, DWORD_Buffer);
    	diskOffset += 20;
    }
    
    free(DWORD_Buffer);
}

void importsConsoleOutput64(FILE* pefile, size_t numID, uint32_t diskOffset, uint16_t numberOfSections, struct SECTION_HEADER* sectionHeader64, struct IMAGE_IMPORT_DESCRIPTOR64** imports64){

	uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
	uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
	uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));
	
	printf("IMPORT INFORMATION\n-----------------------------------\n\n");
	
	for(size_t i=0;i<numID;i++){
		if(!((imports64[i]->u.OriginalFirstThunk.u1.ordinal == 0) && (imports64[i]->timeDateStamp == 0) && (imports64[i]->forwarderChain == 0) && (imports64[i]->name == 0) && (imports64[i]->FirstThunk.u1.addressOfData == 0))){
			printf("[IMPORT_DESCRIPTOR32]\n");
	    		printf("\timports64[%zu]->u.OriginalFirstThunk.u1.ordinal: %04x\n", i, imports64[i]->u.OriginalFirstThunk.u1.ordinal);
	    		printf("\timports64[%zu]->timeDateStamp: %04x\n", i, imports64[i]->timeDateStamp);
	    		printf("\timports64[%zu]->forwarderChain: %04x\n", i, imports64[i]->forwarderChain);
	    		printf("\timports64[%zu]->name: %04x\n", i, imports64[i]->name);
	    		printf("\timports64[%zu]->FirstThunk.u1.addressOfData: %04lx\n\n", i, imports64[i]->FirstThunk.u1.addressOfData);
	    		diskOffset += 20;
	    		
	    		uint32_t dllNameOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(imports64[i]->name), numberOfSections, sectionHeader64);
	    		uint8_t dllLetter = reverse_endianess_uint8_t(readByte(pefile, dllNameOffset, BYTE_Buffer));
		    	printf("\t[");
		    	while(dllLetter != 0 && (imports64[i]->u.OriginalFirstThunk.u1.ordinal != 0)){
		        	printf("%c", dllLetter);
		        	dllNameOffset+=1;
		        	dllLetter = reverse_endianess_uint8_t(readByte(pefile, dllNameOffset, BYTE_Buffer));
		    	}
		    	printf("]\n\n");
		    	
		    	struct IMAGE_THUNK_DATA64 tmpNames;
            
            		uint32_t tmpNamesOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(imports64[i]->u.OriginalFirstThunk.u1.ordinal), numberOfSections, sectionHeader64);
            
            		size_t namesCount=0;
            		tmpNames.u1.ordinal = reverse_endianess_uint64_t(readQWord(pefile, tmpNamesOffset, QWORD_Buffer));
            		while((tmpNames.u1.ordinal != 0)){
    				tmpNamesOffset += sizeof(uint64_t);
            			tmpNames.u1.ordinal = reverse_endianess_uint64_t(readQWord(pefile, tmpNamesOffset, QWORD_Buffer));
            			namesCount++;
            		}
            
            		struct IMAGE_THUNK_DATA64* names = malloc(namesCount * sizeof(struct IMAGE_THUNK_DATA64));
            
            		uint32_t namesOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(imports64[i]->u.OriginalFirstThunk.u1.ordinal), numberOfSections, sectionHeader64);
            
            		for(size_t j=0;j<namesCount;j++){
            			names[j].u1.ordinal = reverse_endianess_uint64_t(readQWord(pefile, namesOffset+j*sizeof(uint64_t), QWORD_Buffer));
            	
            			if(names[j].u1.ordinal != 0){
            				if(names[j].u1.ordinal <= 0x8000000000000000){
            					uint64_t functionNameOffset = convertRelativeAddressToDiskOffset64_t(names[j].u1.ordinal, numberOfSections, sectionHeader64);
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
	free(QWORD_Buffer);

}

void initializeCertificate64(size_t certificateCount, struct IMAGE_CERTIFICATE64* certificate64){

    for(size_t i=0;i<certificateCount;i++){    
            certificate64[i].dwLength = (uint32_t)0;
            certificate64[i].wRevision = (uint16_t)0;
            certificate64[i].wCertificateType = (uint16_t)0;
    }
}

void parseCertificate64(FILE* pefile, uint32_t diskOffset, size_t certificateCount, struct IMAGE_CERTIFICATE64* certificate64, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64){

    uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    size_t i=0;
    
    while(diskOffset < (diskOffset + reverse_endianess_uint32_t(optionalHeader64->dataDirectory[4].size)) && (i < certificateCount)){    
            certificate64[i].dwLength = readDWord(pefile, diskOffset, DWORD_Buffer);
            certificate64[i].wRevision = readWord(pefile, diskOffset+4, WORD_Buffer);
            certificate64[i].wCertificateType = readWord(pefile, diskOffset+6, WORD_Buffer);
            diskOffset += reverse_endianess_uint32_t(certificate64[i++].dwLength);
            while(diskOffset % 8 != 0)
            	diskOffset++;
    }
    
    free(WORD_Buffer);
    free(DWORD_Buffer);

}

void certificateConsoleOutput64(size_t certificateCount, struct IMAGE_CERTIFICATE64* certificate64){
    printf("CERTIFICATE INFORMATION\n-------------------------------------------\n\n");
    for(size_t i=0;i<certificateCount;i++){
    	printf("certificate64[%zu].dwLength: %04x\n", i, reverse_endianess_uint32_t(certificate64[i].dwLength));
    	if(reverse_endianess_uint16_t(certificate64[i].wRevision) == 0x200)
    	    printf("certificate64[%zu].wRevision: WIN_CERT_REVISION_2_0\n", i);
    	else
    	    printf("certificate64[%zu].wRevision: WIN_CERT_REVISION_1_0\n", i);
    	printf("certificate64[%zu].wCertificateType: %02x\n\n", i, reverse_endianess_uint16_t(certificate64[i].wCertificateType));
    }

    printf("\n\n");
}

void initializeTLS64(struct IMAGE_TLS_DIRECTORY64* tls64){

    tls64->startAddressOfRawData = (uint64_t)0;
    tls64->endAddressOfRawData = (uint64_t)0;
    tls64->addressOfIndex = (uint64_t)0;
    tls64->addressOfCallBacks = (uint64_t)0;
    tls64->sizeOfZeroFill = (uint32_t)0;
    tls64->characteristics = (uint32_t)0;
}

void parseTLS64(FILE* pefile, uint32_t diskOffset, struct IMAGE_TLS_DIRECTORY64* tls64){
	uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
	uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));
	
	tls64->startAddressOfRawData = readQWord(pefile, diskOffset, QWORD_Buffer);
	tls64->endAddressOfRawData = readQWord(pefile, diskOffset+4, QWORD_Buffer);
	tls64->addressOfIndex = readQWord(pefile, diskOffset+8, QWORD_Buffer);
	tls64->addressOfCallBacks = readQWord(pefile, diskOffset+12, QWORD_Buffer);
	tls64->sizeOfZeroFill = readDWord(pefile, diskOffset+16, DWORD_Buffer);
  	tls64->characteristics = readDWord(pefile, diskOffset+20, DWORD_Buffer);

	free(DWORD_Buffer);
	free(QWORD_Buffer);
}

void tlsConsoleOutput64(struct IMAGE_TLS_DIRECTORY64* tls64){

	printf("TLS Information\n---------------------------------\n");
	printf("tls64->startAddressOfRawData: %04lx\n", reverse_endianess_uint64_t(tls64->startAddressOfRawData));
	printf("tls64->endAddressOfRawData: %04lx\n", reverse_endianess_uint64_t(tls64->endAddressOfRawData));
	printf("tls64->addressOfIndex: %04lx\n", reverse_endianess_uint64_t(tls64->addressOfIndex));
	printf("tls64->addressOfCallBacks: %04lx\n", reverse_endianess_uint64_t(tls64->addressOfCallBacks));
	printf("tls64->sizeOfZeroFill: %04x\n", reverse_endianess_uint32_t(tls64->sizeOfZeroFill));
	printf("tls64->characteristics: %04x\n\n\n", reverse_endianess_uint32_t(tls64->characteristics));

}

void initializeLoadConfig64(struct IMAGE_LOAD_CONFIG64* loadConfig64){

        loadConfig64->characteristics = (uint32_t)0;
    	loadConfig64->timeDateStamp = (uint32_t)0;
    	loadConfig64->majorVersion = (uint16_t)0;
    	loadConfig64->minorVersion = (uint16_t)0;
    	loadConfig64->globalFlagsClear = (uint32_t)0;
    	loadConfig64->globalFlagsSet = (uint32_t)0;
    	loadConfig64->criticalSectionDefaultTimeout = (uint32_t)0;
    	loadConfig64->deCommitFreeBlockThreshold = (uint64_t)0;
    	loadConfig64->deCommitTotalFreeThreshold = (uint64_t)0;
    	loadConfig64->lockPrefixTable = (uint64_t)0;
    	loadConfig64->maximumAllocationSize = (uint64_t)0;
    	loadConfig64->virtualMemoryThreshold = (uint64_t)0;
    	loadConfig64->processAffinityMask = (uint64_t)0;
    	loadConfig64->processHeapFlags = (uint32_t)0;
    	loadConfig64->cSDVersion = (uint16_t)0;
    	loadConfig64->reserved = (uint16_t)0;
    	loadConfig64->editList = (uint64_t)0;
    	loadConfig64->securityCookie = (uint64_t)0;
    	loadConfig64->sEHandlerTable = (uint64_t)0;
    	loadConfig64->sEHandlerCount = (uint64_t)0;
    	loadConfig64->guardCFCheckFunctionPointer = (uint64_t)0;
    	loadConfig64->guardCFDispatchFunctionPointer = (uint64_t)0;
    	loadConfig64->guardCFFunctionTable = (uint64_t)0;
    	loadConfig64->guardCFFunctionCount = (uint64_t)0;
    	loadConfig64->guardFlags = (uint32_t)0;
    	loadConfig64->codeIntegrity[0] = (uint32_t)0;
    	loadConfig64->codeIntegrity[1] = (uint32_t)0;
    	loadConfig64->codeIntegrity[2] = (uint32_t)0;
    	loadConfig64->guardAddressTakenIatEntryTable = (uint64_t)0;
    	loadConfig64->guardAddressTakenIatEntryCount = (uint64_t)0;
    	loadConfig64->guardLongJumpTargetTable = (uint64_t)0;
    	loadConfig64->guardLongJumpTargetCount = (uint64_t)0;
}

void parseLoadConfig64(FILE* pefile, uint32_t diskOffset, struct IMAGE_LOAD_CONFIG64* loadConfig64){
	uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    	uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    	uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));
    	
    	loadConfig64->characteristics = readDWord(pefile, diskOffset, DWORD_Buffer);
    	loadConfig64->timeDateStamp = readDWord(pefile, diskOffset+4, DWORD_Buffer);
    	loadConfig64->majorVersion = readWord(pefile, diskOffset+8, WORD_Buffer);
    	loadConfig64->minorVersion = readWord(pefile, diskOffset+10, WORD_Buffer);
    	loadConfig64->globalFlagsClear = readDWord(pefile, diskOffset+12, DWORD_Buffer);
    	loadConfig64->globalFlagsSet = readDWord(pefile, diskOffset+16, DWORD_Buffer);
    	loadConfig64->criticalSectionDefaultTimeout = readDWord(pefile, diskOffset+20, DWORD_Buffer);
    	loadConfig64->deCommitFreeBlockThreshold = readQWord(pefile, diskOffset+24, QWORD_Buffer);
    	loadConfig64->deCommitTotalFreeThreshold = readQWord(pefile, diskOffset+32, QWORD_Buffer);
    	loadConfig64->lockPrefixTable = readQWord(pefile, diskOffset+40, QWORD_Buffer);
    	loadConfig64->maximumAllocationSize = readQWord(pefile, diskOffset+48, QWORD_Buffer);
    	loadConfig64->virtualMemoryThreshold = readQWord(pefile, diskOffset+56, QWORD_Buffer);
    	loadConfig64->processAffinityMask = readQWord(pefile, diskOffset+64, QWORD_Buffer);
    	loadConfig64->processHeapFlags = readDWord(pefile, diskOffset+72, DWORD_Buffer);
    	loadConfig64->cSDVersion = readWord(pefile, diskOffset+76, WORD_Buffer);
    	loadConfig64->reserved = readWord(pefile, diskOffset+78, WORD_Buffer);
    	loadConfig64->editList = readQWord(pefile, diskOffset+80, QWORD_Buffer);
    	loadConfig64->securityCookie = readQWord(pefile, diskOffset+88, QWORD_Buffer);
    	loadConfig64->sEHandlerTable = readQWord(pefile, diskOffset+96, QWORD_Buffer);
    	loadConfig64->sEHandlerCount = readQWord(pefile, diskOffset+104, QWORD_Buffer);
    	loadConfig64->guardCFCheckFunctionPointer = readQWord(pefile, diskOffset+112, QWORD_Buffer);
    	loadConfig64->guardCFDispatchFunctionPointer = readQWord(pefile, diskOffset+120, QWORD_Buffer);
    	loadConfig64->guardCFFunctionTable = readQWord(pefile, diskOffset+128, QWORD_Buffer);
    	loadConfig64->guardCFFunctionCount = readQWord(pefile, diskOffset+136, QWORD_Buffer);
    	loadConfig64->guardFlags = readDWord(pefile, diskOffset+144, DWORD_Buffer);
    	loadConfig64->codeIntegrity[0] = readDWord(pefile, diskOffset+148, DWORD_Buffer);
    	loadConfig64->codeIntegrity[1] = readDWord(pefile, diskOffset+152, DWORD_Buffer);
    	loadConfig64->codeIntegrity[2] = readDWord(pefile, diskOffset+156, DWORD_Buffer);
    	loadConfig64->guardAddressTakenIatEntryTable = readQWord(pefile, diskOffset+160, QWORD_Buffer);
    	loadConfig64->guardAddressTakenIatEntryCount = readQWord(pefile, diskOffset+168, QWORD_Buffer);
    	loadConfig64->guardLongJumpTargetTable = readQWord(pefile, diskOffset+176, QWORD_Buffer);
    	loadConfig64->guardLongJumpTargetCount = readQWord(pefile, diskOffset+184, QWORD_Buffer);
    	
    	free(WORD_Buffer);
    	free(DWORD_Buffer);
    	free(QWORD_Buffer);
}

void loadConfigConsoleOutput64(struct IMAGE_LOAD_CONFIG64* loadConfig64){

        printf("LOAD CONFIG INFORMATION\n-----------------------------------\n\n");
	printf(
            "loadConfig64->characteristics: 0x%04x\n"
            "loadConfig64->timeDateStamp: 0x%04x\n"
            "loadConfig64->majorVersion: 0x%02x\n"
            "loadConfig64->minorVersion: 0x%02x\n"
            "loadConfig64->globalFlagsClear: 0x%04x\n"
            "loadConfig64->globalFlagsSet: 0x%04x\n"
            "loadConfig64->criticalSectionDefaultTimeout: 0x%04x\n"
            "loadConfig64->deCommitFreeBlockThreshold: 0x%04lx\n"
            "loadConfig64->deCommitTotalFreeThreshold: 0x%04lx\n"
            "loadConfig64->lockPrefixTable: 0x%04lx\n"
            "loadConfig64->maximumAllocationSize: 0x%04lx\n"
            "loadConfig64->virtualMemoryThreshold: 0x%04lx\n"
            "loadConfig64->processAffinityMask: 0x%04lx\n"
            "loadConfig64->processHeapFlags: 0x%04x\n"
            "loadConfig64->cSDVersion: 0x%02x\n"
            "loadConfig64->reserved: 0x%02x\n"
            "loadConfig64->editList: 0x%04lx\n"
            "loadConfig64->securityCookie: 0x%04lx\n"
            "loadConfig64->sEHandlerTable: 0x%04lx\n"
            "loadConfig64->sEHandlerCount: 0x%04lx\n"
            "loadConfig64->guardCFCheckFunctionPointer: 0x%04lx\n"
            "loadConfig64->guardCFDispatchFunctionPointer: 0x%04lx\n"
            "loadConfig64->guardCFFunctionTable: 0x%04lx\n"
            "loadConfig64->guardCFFunctionCount: 0x%04lx\n"
            "loadConfig64->guardFlags: 0x%04x\n"
            "loadConfig64->codeIntegrity[0]: 0x%04x\n"
            "loadConfig64->codeIntegrity[1]: 0x%04x\n"
            "loadConfig64->codeIntegrity[2]: 0x%04x\n"
            "loadConfig64->guardAddressTakenIatEntryTable: 0x%04lx\n"
            "loadConfig64->guardAddressTakenIatEntryCount: 0x%04lx\n"
            "loadConfig64->guardLongJumpTargetTable: 0x%04lx\n"
            "loadConfig64->guardLongJumpTargetCount: 0x%04lx\n"
            ,reverse_endianess_uint32_t(loadConfig64->characteristics), reverse_endianess_uint32_t(loadConfig64->timeDateStamp)
            ,reverse_endianess_uint16_t(loadConfig64->majorVersion), reverse_endianess_uint16_t(loadConfig64->minorVersion)
            ,reverse_endianess_uint32_t(loadConfig64->globalFlagsClear), reverse_endianess_uint32_t(loadConfig64->globalFlagsSet)
            ,reverse_endianess_uint32_t(loadConfig64->criticalSectionDefaultTimeout), reverse_endianess_uint64_t(loadConfig64->deCommitFreeBlockThreshold)
            ,reverse_endianess_uint64_t(loadConfig64->deCommitTotalFreeThreshold)
            ,reverse_endianess_uint64_t(loadConfig64->lockPrefixTable), reverse_endianess_uint64_t(loadConfig64->maximumAllocationSize)
            ,reverse_endianess_uint64_t(loadConfig64->virtualMemoryThreshold), reverse_endianess_uint64_t(loadConfig64->processAffinityMask)
            ,reverse_endianess_uint32_t(loadConfig64->processHeapFlags), reverse_endianess_uint16_t(loadConfig64->cSDVersion)
            ,reverse_endianess_uint16_t(loadConfig64->reserved), reverse_endianess_uint64_t(loadConfig64->editList)
            ,reverse_endianess_uint64_t(loadConfig64->securityCookie), reverse_endianess_uint64_t(loadConfig64->sEHandlerTable)
            ,reverse_endianess_uint64_t(loadConfig64->sEHandlerCount), reverse_endianess_uint64_t(loadConfig64->guardCFCheckFunctionPointer)
            ,reverse_endianess_uint64_t(loadConfig64->guardCFDispatchFunctionPointer), reverse_endianess_uint64_t(loadConfig64->guardCFFunctionTable)
            ,reverse_endianess_uint64_t(loadConfig64->guardCFFunctionCount), reverse_endianess_uint32_t(loadConfig64->guardFlags)
            ,reverse_endianess_uint32_t(loadConfig64->codeIntegrity[0]), reverse_endianess_uint32_t(loadConfig64->codeIntegrity[1])
            ,reverse_endianess_uint32_t(loadConfig64->codeIntegrity[2]), reverse_endianess_uint64_t(loadConfig64->guardAddressTakenIatEntryTable)
            ,reverse_endianess_uint64_t(loadConfig64->guardAddressTakenIatEntryCount), reverse_endianess_uint64_t(loadConfig64->guardLongJumpTargetTable)
            ,reverse_endianess_uint64_t(loadConfig64->guardLongJumpTargetCount)
        );
}

void consoleOutput64(struct IMAGE_DOS_HEADER* msDOSHeader, struct IMAGE_COFF_HEADER* coffHeader, struct IMAGE_OPTIONAL_HEADER64* optionalHeader64, struct SECTION_HEADER* sectionHeader64){

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
    "msDOSHeader->e_res2: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
    "msDOSHeader->e_lfanew: 0x%04x\n\n"
    ,msDOSHeader->e_magic, msDOSHeader->e_cblp, msDOSHeader->e_cp, msDOSHeader->e_crlc
    ,msDOSHeader->e_cparhdr, msDOSHeader->e_minalloc, msDOSHeader->e_maxalloc, msDOSHeader->e_ss
    ,msDOSHeader->e_sp, msDOSHeader->e_csum, msDOSHeader->e_ip, msDOSHeader->e_cs
    ,msDOSHeader->e_lfarlc, msDOSHeader->e_ovno, msDOSHeader->e_res[0], msDOSHeader->e_res[1]
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
    "optionalHeader64->magic: 0x%02x\n"
    "optionalHeader64->majorLinkerVersion: 0x%x\n"
    "optionalHeader64->minorLinkerVersion: 0x%x\n"
    "optionalHeader64->sizeOfCode: 0x%04x\n"
    "optionalHeader64->sizeOfInitializedData: 0x%04x\n"
    "optionalHeader64->sizeOfUninitializedData: 0x%04x\n"
    "optionalHeader64->addressOfEntryPoint: 0x%04x\n"
    "optionalHeader64->baseOfCode: 0x%04x\n"
    "optionalHeader64->imageBase: 0x%04lx\n"
    "optionalHeader64->sectionAlignment: 0x%04lx\n"
    "optionalHeader64->fileAlignment: 0x%04lx\n"
    "optionalHeader64->majorOperatingSystemVersion: 0x%02x\n"
    "optionalHeader64->minorOperatingSystemVersion: 0x%02x\n"
    "optionalHeader64->majorImageVersion: 0x%02x\n"
    "optionalHeader64->minorImageVersion: 0x%02x\n"
    "optionalHeader64->majorSubsystemVersion: 0x%02x\n"
    "optionalHeader64->minorSubsystemVersion: 0x%02x\n"
    "optionalHeader64->win32VersionValue: 0x%04x\n"
    "optionalHeader64->sizeOfImage: 0x%04x\n"
    "optionalHeader64->sizeOfHeaders: 0x%04x\n"
    "optionalHeader64->checksum: 0x%04x\n"
    "optionalHeader64->subsystem: 0x%02x\n"
    "optionalHeader64->dllCharacteristics: 0x%04x\n"
    "optionalHeader64->sizeOfStackReserve: 0x%04lx\n"
    "optionalHeader64->sizeOfStackCommit: 0x%04lx\n"
    "optionalHeader64->sizeOfHeapReserve: 0x%04lx\n"
    "optionalHeader64->sizeOfHeapCommit: 0x%04lx\n"
    "optionalHeader64->loaderFlags: 0x%04x\n"
    "optionalHeader64->numberOfRvaAndSizes: 0x%04x\n"
    ,reverse_endianess_uint16_t(optionalHeader64->magic), reverse_endianess_uint8_t(optionalHeader64->majorLinkerVersion)
    ,reverse_endianess_uint8_t(optionalHeader64->minorLinkerVersion), reverse_endianess_uint32_t(optionalHeader64->sizeOfCode)
    ,reverse_endianess_uint32_t(optionalHeader64->sizeOfInitializedData), reverse_endianess_uint32_t(optionalHeader64->sizeOfUninitializedData)
    ,reverse_endianess_uint32_t(optionalHeader64->addressOfEntryPoint), reverse_endianess_uint32_t(optionalHeader64->baseOfCode)
    ,reverse_endianess_uint64_t(optionalHeader64->imageBase)
    ,reverse_endianess_uint64_t(optionalHeader64->sectionAlignment), reverse_endianess_uint64_t(optionalHeader64->fileAlignment)
    ,reverse_endianess_uint16_t(optionalHeader64->majorOperatingSystemVersion), reverse_endianess_uint16_t(optionalHeader64->minorOperatingSystemVersion)
    ,reverse_endianess_uint16_t(optionalHeader64->majorImageVersion), reverse_endianess_uint16_t(optionalHeader64->minorImageVersion)
    ,reverse_endianess_uint16_t(optionalHeader64->majorSubsystemVersion), reverse_endianess_uint16_t(optionalHeader64->minorSubsystemVersion)
    ,reverse_endianess_uint32_t(optionalHeader64->win32VersionValue), reverse_endianess_uint32_t(optionalHeader64->sizeOfImage)
    ,reverse_endianess_uint32_t(optionalHeader64->sizeOfHeaders), reverse_endianess_uint32_t(optionalHeader64->checksum)
    ,reverse_endianess_uint16_t(optionalHeader64->subsystem), reverse_endianess_uint16_t(optionalHeader64->dllCharacteristics)
    ,reverse_endianess_uint64_t(optionalHeader64->sizeOfStackReserve), reverse_endianess_uint64_t(optionalHeader64->sizeOfStackCommit)
    ,reverse_endianess_uint64_t(optionalHeader64->sizeOfHeapReserve), reverse_endianess_uint64_t(optionalHeader64->sizeOfHeapCommit)
    ,reverse_endianess_uint32_t(optionalHeader64->loaderFlags), reverse_endianess_uint32_t(optionalHeader64->numberOfRvaAndSizes)
    );
    printf("\n\tData Directories:\n\n");
    for(size_t i=0;i<16;i++){
        if((optionalHeader64->dataDirectory[i].virtualAddress != 0) && (optionalHeader64->dataDirectory[i].size != 0)){
            printf(
            "\tData Directory: %s\n"
            "\t\tVirtualAddress: 0x%02x\n"
            "\t\tSize: 0x%02x\n"

            ,dataDirectoryList[i]
            ,reverse_endianess_uint32_t(optionalHeader64->dataDirectory[i].virtualAddress)
            ,reverse_endianess_uint32_t(optionalHeader64->dataDirectory[i].size)
            );
        }
    }

    printf("\n\n\n\nSection Headers\n---------------\n");
    for(size_t i=0;i<convert_WORD_To_uint16_t(coffHeader->numberOfSections);i++){
        if(sectionHeader64[i].name != 0){
            char* sectionNameBuf = malloc(1024 * sizeof(char));
            strcpy(sectionNameBuf, "INITIALIZED_VALUE");
            char* sectionName = convert_uint64_t_ToString(sectionHeader64[i].name, sectionNameBuf);
            printf("sectionHeader64.name: 0x%04lx\t(%s)\n"
            "\tsectionHeader64.virtualSize: 0x%04x\n"
            "\tsectionHeader64.virtualAddress: 0x%04x\n"
            "\tsectionHeader64.sizeOfRawData: 0x%04x\n"
            "\tsectionHeader64.pointerToRawData: 0x%04x\n"
            "\tsectionHeader64.pointerToRelocations: 0x%04x\n"
            "\tsectionHeader64.pointerToLineNumbers: 0x%04x\n"
            "\tsectionHeader64.numberOfRelocations: 0x%02x\n"
            "\tsectionHeader64.numberOfLineNumbers: 0x%02x\n"
            "\tsectionHeader64.characteristics: 0x%04x\n\n"
            ,sectionHeader64[i].name, sectionName, sectionHeader64[i].virtualSize, sectionHeader64[i].virtualAddress, sectionHeader64[i].sizeOfRawData
            ,sectionHeader64[i].pointerToRawData, sectionHeader64[i].pointerToRelocations, sectionHeader64[i].pointerToLineNumbers
            ,sectionHeader64[i].numberOfRelocations, sectionHeader64[i].numberOfLineNumbers, sectionHeader64[i].characteristics);
            free(sectionNameBuf);
        }
    }
    
}


void parsePE64(FILE* pefile, struct switchList* psList){
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
    }
    	
    struct IMAGE_OPTIONAL_HEADER64* optionalHeader64 = malloc(sizeof(struct IMAGE_OPTIONAL_HEADER64));
    if(optionalHeader64 == NULL){
    	perror("Failed to allocate memory for optionalHeader64 structure");
    	return;
    }
    initializeOptionalHeader64(optionalHeader64);
    
    optionalHeader64->subsystemType = malloc(41 * sizeof(char));
    if(optionalHeader64->subsystemType == NULL){
    	perror("Failed to allocate memory for optionalHeader64->subsystemType structure");
    	return;
    }
    memcpy(optionalHeader64->subsystemType, "SUBSYSTEM_INITIALIZATION_VALUE", 31);
    
    optionalHeader64->dllCharacteristicsList = malloc(16 * sizeof(char*));
    if(optionalHeader64->dllCharacteristicsList == NULL){
    	perror("Failed to allocate memory for optionalHeader64->dllCharacteristicsList structure");
    	return;
    }
    
    for(size_t i=0;i<16;i++){
    	optionalHeader64->dllCharacteristicsList[i] = malloc(47 * sizeof(char));
    	if(optionalHeader64->dllCharacteristicsList[i] == NULL){
    		perror("Failed to allocate memory for optionalHeader64->dllCharacteristicsList structure");
    		return;
    	}
    	memcpy(optionalHeader64->dllCharacteristicsList[i], "DLL_INITIALIZATION_VALUE", 21);
    }
    

    parseMSDOSHeader(pefile, msDOSHeader);
    parseCoffHeader(pefile, convert_DWORD_To_uint32_t(msDOSHeader->e_lfanew), coffHeader);
    parseOptionalHeader64(pefile, convert_DWORD_To_uint32_t(msDOSHeader->e_lfanew), optionalHeader64);
    
    uint16_t numberOfSections = convert_WORD_To_uint16_t(coffHeader->numberOfSections);
    uint32_t memoryOffset = convert_DWORD_To_uint32_t(msDOSHeader->e_lfanew) + 24 + convert_WORD_To_uint16_t(coffHeader->sizeOfOptionalHeader);
    struct SECTION_HEADER* sectionHeader64 = malloc(numberOfSections * sizeof(struct SECTION_HEADER));

    if(sectionHeader64 == NULL){
    	perror("Failed to allocate memory for sectionHeader64 structure\n");
    	return;
    }
    initializeSectionHeader(numberOfSections, sectionHeader64);
    
    parseSectionHeaders(pefile, numberOfSections, memoryOffset, sectionHeader64);
    
    if(!psList->exportResult){
    	consoleOutput64(msDOSHeader, coffHeader, optionalHeader64, sectionHeader64);
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[0].virtualAddress) != 0){
    	printf("Export Data Directory present!: %04x\n\n", reverse_endianess_uint32_t(optionalHeader64->dataDirectory[0].virtualAddress));
    	struct IMAGE_EXPORT_DIRECTORY64* exports64 = malloc(sizeof(struct IMAGE_EXPORT_DIRECTORY64));
        if(exports64 == NULL){
    	    printf("Failed to allocate memory for exports64 structure\n");
    	    return;
        }
        initializeExportDirectory64(exports64);
        
        uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[0].virtualAddress), numberOfSections, sectionHeader64);
        
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
        
        parseExports64(pefile, diskOffset, numberOfSections, sectionHeader64, exports64, exportFunctionAddresses, exportFunctionNames, exportOrdinalAddresses);
        
        if(!psList->exportResult)
        	exportsConsoleOutput64(pefile, optionalHeader64, exports64, exportFunctionAddresses, exportFunctionNames, exportOrdinalAddresses, numberOfSections, sectionHeader64);
        
        free(exports64);
        free(exportFunctionAddresses);
        free(exportFunctionNames);
        free(exportOrdinalAddresses);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[1].virtualAddress) != 0){
    	struct IMAGE_IMPORT_DESCRIPTOR64** imports64 = malloc(sizeof(struct IMAGE_IMPORT_DESCRIPTOR64*));
    	if(imports64 == NULL){
    	    perror("Failed to allocate memory for imports64 structure\n");
    	    return;
    	}
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[1].virtualAddress), numberOfSections, sectionHeader64);
    	uint32_t tmpDiskOffset = diskOffset;
    	size_t numID=0;
    	
    	struct IMAGE_IMPORT_DESCRIPTOR64* tmpImports64 = malloc(sizeof(struct IMAGE_IMPORT_DESCRIPTOR64));
    	
    	tmpImports64->u.OriginalFirstThunk.u1.ordinal = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    	tmpImports64->timeDateStamp = readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer);
    	tmpImports64->forwarderChain = readDWord(pefile, tmpDiskOffset+8, DWORD_Buffer);
    	tmpImports64->name = readDWord(pefile, tmpDiskOffset+12, DWORD_Buffer);
    	tmpImports64->FirstThunk.u1.addressOfData = readDWord(pefile, tmpDiskOffset+16, DWORD_Buffer);
    	
    	while(!((tmpImports64->u.OriginalFirstThunk.u1.ordinal == 0) && (tmpImports64->timeDateStamp == 0) && (tmpImports64->forwarderChain == 0) && (tmpImports64->name == 0) && (tmpImports64->FirstThunk.u1.addressOfData == 0))){
    		tmpImports64->u.OriginalFirstThunk.u1.ordinal = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    		tmpImports64->timeDateStamp = readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer);
    		tmpImports64->forwarderChain = readDWord(pefile, tmpDiskOffset+8, DWORD_Buffer);
    		tmpImports64->name = readDWord(pefile, tmpDiskOffset+12, DWORD_Buffer);
    		tmpImports64->FirstThunk.u1.addressOfData = readDWord(pefile, tmpDiskOffset+16, DWORD_Buffer);
    		tmpDiskOffset += 20;
    		numID++;
    	}
    	
    	imports64 = realloc(imports64, (numID+1)*sizeof(struct IMAGE_IMPORT_DESCRIPTOR64*));
    	if(imports64 == NULL){
    		perror("Failed to reallocate memory for imports64\n");
    		return;
    	}
    	for(size_t i=0;i<numID;i++){
    		imports64[i] = malloc(sizeof(struct IMAGE_IMPORT_DESCRIPTOR64));
    		if(imports64[i] == NULL){
    			perror("Failed to allocate memory for IMAGE_IMPORT_DESCRIPTOR64\n");
    			return;
    		}
    		initializeImportDescriptor64(imports64[i]);
    	}
    	
    	parseImports64(pefile, numID, diskOffset, imports64);
    	importsConsoleOutput64(pefile, numID, diskOffset, numberOfSections, sectionHeader64, imports64);
    	
    	free(tmpImports64);
    	for(size_t i=0;i<numID;i++)
    		free(imports64[i]);
    	free(imports64);
    }
    
    if((reverse_endianess_uint16_t(optionalHeader64->magic) == 0x20b) && (reverse_endianess_uint32_t(optionalHeader64->dataDirectory[3].virtualAddress) != 0)){
    
        uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[3].virtualAddress), numberOfSections, sectionHeader64);
        uint32_t tmpDiskOffset = diskOffset;
        size_t exceptionCount = 0;
    
        struct IMAGE_EXCEPTION tmpexception64;
        
        tmpexception64.startAddress = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
        tmpexception64.endAddress = readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer);
        tmpexception64.unwindAddress = readDWord(pefile, tmpDiskOffset+8, DWORD_Buffer);
        if((tmpexception64.startAddress != 0) && (tmpexception64.endAddress != 0) && (tmpexception64.unwindAddress != 0)){
            tmpDiskOffset += 12;
            exceptionCount++;
        }
            
        while((tmpexception64.startAddress != 0) && (tmpexception64.endAddress != 0) && (tmpexception64.unwindAddress != 0)){
            tmpexception64.startAddress = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
            tmpexception64.endAddress = readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer);
            tmpexception64.unwindAddress = readDWord(pefile, tmpDiskOffset+8, DWORD_Buffer);
            tmpDiskOffset += 12;
            exceptionCount++;
        }
    
    
    	struct IMAGE_EXCEPTION* exception64 = malloc(exceptionCount * sizeof(struct IMAGE_EXCEPTION));
    	if(exception64 == NULL){
    	    perror("Failed to allocate memory for exception32");
    	    return;
    	
    	}
    	initializeException(exceptionCount, exception64);
    	
    	parseException(pefile, diskOffset, exceptionCount, exception64);
    	exceptionConsoleOutput(exceptionCount, exception64);
    	
    	free(exception64);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[4].virtualAddress) != 0){
        uint32_t diskOffset = reverse_endianess_uint32_t(optionalHeader64->dataDirectory[4].virtualAddress);
        uint32_t tmpDiskOffset = diskOffset;
        size_t certificateCount = 0;
        
        struct IMAGE_CERTIFICATE64 tmpCertificate64;
        tmpCertificate64.dwLength = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
        tmpCertificate64.wRevision = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
        tmpCertificate64.wCertificateType = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
        tmpDiskOffset += reverse_endianess_uint32_t(tmpCertificate64.dwLength);
        while(tmpDiskOffset % 8 != 0)
            tmpDiskOffset++;
        certificateCount++;

        while(tmpDiskOffset < (diskOffset + reverse_endianess_uint32_t(optionalHeader64->dataDirectory[4].size))){
            
            tmpCertificate64.dwLength = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
            tmpCertificate64.wRevision = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
            tmpCertificate64.wCertificateType = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
            tmpDiskOffset += reverse_endianess_uint32_t(tmpCertificate64.dwLength);
            while(tmpDiskOffset % 8 != 0)
            	tmpDiskOffset++;
            certificateCount++;
        }
        
        struct IMAGE_CERTIFICATE64* certificate64 = malloc(certificateCount * sizeof(struct IMAGE_CERTIFICATE64));
        if(certificate64 == NULL){
            perror("Failed to allocate memory for certificate64");
            return;
        }
        initializeCertificate64(certificateCount, certificate64);
        parseCertificate64(pefile, diskOffset, certificateCount, certificate64, optionalHeader64);
        certificateConsoleOutput64(certificateCount, certificate64);
        free(certificate64);
    
    }
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[5].virtualAddress) != 0){
	   struct IMAGE_BASE_RELOCATION* baseReloc64 = malloc(sizeof(struct IMAGE_BASE_RELOCATION));
	    if(baseReloc64 == NULL){
		    perror("Failed to allocate memory for baseReloc64");
		    return;
	    }
	    initializeBaseReloc(1, baseReloc64);
	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[5].virtualAddress), numberOfSections, sectionHeader64);
    	uint32_t tmpDiskOffset = diskOffset;
    	
    	baseReloc64->pageRVA = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset, DWORD_Buffer));
     	baseReloc64->blockSize = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer));
     	
     	tmpDiskOffset += 8;
     	size_t baseRelocCount = 0;
    	uint32_t typeCount = 0;
    	
    	while((baseReloc64->pageRVA != 0) && (baseReloc64->blockSize != 0)){
    		baseRelocCount++;
        	typeCount = (baseReloc64->blockSize - 8) / 2;
        	
        	tmpDiskOffset += typeCount * 2;

        	baseReloc64->pageRVA = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset, DWORD_Buffer));
        	baseReloc64->blockSize = reverse_endianess_uint32_t(readDWord(pefile, tmpDiskOffset+4, DWORD_Buffer));
        	tmpDiskOffset += 8;
    	}
    	
    	free(baseReloc64);
    	baseReloc64 = malloc(baseRelocCount * sizeof(struct IMAGE_BASE_RELOCATION));
    	if(baseReloc64 == NULL){
    	    perror("Failed to allocate memory for baseReloc64");
    	}
    	initializeBaseReloc(baseRelocCount, baseReloc64);

    	parseBaseReloc(pefile, diskOffset, baseRelocCount, baseReloc64);
    	baseRelocConsoleOutput(pefile, diskOffset, baseRelocCount, baseReloc64);
    	free(baseReloc64);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[6].virtualAddress) != 0){
    	size_t debugCount = reverse_endianess_uint32_t(optionalHeader64->dataDirectory[6].size / sizeof(struct IMAGE_DEBUG_DIRECTORY));
    	struct IMAGE_DEBUG_DIRECTORY* debug64 = malloc(debugCount * sizeof(struct IMAGE_DEBUG_DIRECTORY));
    	if(debug64 == NULL){
    		perror("Failed to allocate memory for debug64");
    		return;
    	}
    	initializeDebug(debugCount, debug64);
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[6].virtualAddress), numberOfSections, sectionHeader64);
    	
    	parseDebug(pefile, debugCount, diskOffset, debug64);
    	debugConsoleOutput(pefile, debugCount, debug64, sectionHeader64);
    	free(debug64);
    
    }
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[9].virtualAddress) != 0){
    	struct IMAGE_TLS_DIRECTORY64* tls64 = malloc(sizeof(struct IMAGE_TLS_DIRECTORY64));
    	if(tls64 == NULL){
    	    perror("Failed to allocate memory for tls64");
    	    return;
    	}
    	initializeTLS64(tls64);
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[9].virtualAddress), numberOfSections, sectionHeader64);
    	parseTLS64(pefile, diskOffset, tls64);
    	tlsConsoleOutput64(tls64);
    	free(tls64);
    
    }
    
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[10].virtualAddress) != 0){
    	struct IMAGE_LOAD_CONFIG64* loadConfig64 = malloc(sizeof(struct IMAGE_LOAD_CONFIG64));
    	if(loadConfig64 == NULL){
    		perror("Failed to allocate memory for loadConfig64");
    		return;
    	}
    	initializeLoadConfig64(loadConfig64);
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[10].virtualAddress), numberOfSections, sectionHeader64);
    	
    	parseLoadConfig64(pefile, diskOffset, loadConfig64);
    	loadConfigConsoleOutput64(loadConfig64);
    	free(loadConfig64);
    }
    
    if(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[11].virtualAddress) != 0){
    	struct IMAGE_BOUND_IMPORT_DESCRIPTOR tmpBounds64;
    	uint32_t tmpDiskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[11].virtualAddress), numberOfSections, sectionHeader64);
    	uint32_t boundsCount = 0;
    	
    	tmpBounds64.timestamp = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    	tmpBounds64.offsetModuleName = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
    	tmpBounds64.numberOfModuleForwarderRefs = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
    	boundsCount++;
    	tmpDiskOffset += 8;
    	
    	while((tmpBounds64.timestamp != 0) && (tmpBounds64.offsetModuleName != 0) && (tmpBounds64.numberOfModuleForwarderRefs != 0)){
    		
    		if(tmpBounds64.numberOfModuleForwarderRefs != 0){
    			struct IMAGE_BOUND_FORWARDER_REF tmpForwards64;
    			while((tmpForwards64.timestamp != 0) && (tmpForwards64.offsetModuleName != 0) && (tmpForwards64.reserved != 0)){
    				tmpForwards64.timestamp = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    				tmpForwards64.offsetModuleName = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
    				tmpForwards64.reserved = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
    				tmpDiskOffset += 8;
    			}
    		}
    		
    		boundsCount++;
    		tmpDiskOffset += 8;
    		
    		tmpBounds64.timestamp = readDWord(pefile, tmpDiskOffset, DWORD_Buffer);
    		tmpBounds64.offsetModuleName = readWord(pefile, tmpDiskOffset+4, WORD_Buffer);
    		tmpBounds64.numberOfModuleForwarderRefs = readWord(pefile, tmpDiskOffset+6, WORD_Buffer);
    	}
    	
    	struct IMAGE_BOUND_IMPORT_DESCRIPTOR* bounds64 = malloc(boundsCount * sizeof(struct IMAGE_BOUND_IMPORT_DESCRIPTOR));
    	if(bounds64 == NULL){
    		perror("Failed to allocate memory for bounds64");
    		return;
    	}
    	initializeBoundImport(boundsCount, bounds64);
    	
    	uint32_t diskOffset = convertRelativeAddressToDiskOffset(reverse_endianess_uint32_t(optionalHeader64->dataDirectory[11].virtualAddress), numberOfSections, sectionHeader64);
    	parseBoundImport(pefile, diskOffset, boundsCount, bounds64);
    	boundsConsoleOutput(boundsCount, bounds64);
    	
    	free(bounds64);
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
    	
    for(size_t i=0;i<17;i++)
    	free(coffHeader->characteristicsList[i]);
    	
    for(size_t i=0;i<16;i++)
    	free(optionalHeader64->dllCharacteristicsList[i]);
	
    free(msDOSHeader);
    free(coffHeader->machineArchitecture);
    free(coffHeader->characteristicsList);
    free(coffHeader);
    free(optionalHeader64->subsystemType);
    free(optionalHeader64->dllCharacteristicsList);
    free(optionalHeader64);
    free(sectionHeader64);
    free(WORD_Buffer);
    free(DWORD_Buffer);
    free(QWORD_Buffer);

 }

}
