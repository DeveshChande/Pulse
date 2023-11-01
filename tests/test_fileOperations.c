#include "test_fileOperations.h"

void test_reverse_endianess_uint8_t(void** state){
	uint8_t value = 52;
	uint8_t resultat = reverse_endianess_uint8_t(value);
	assert_int_equal(resultat, 0x34);
	(void) state;
}

void test_reverse_endianess_uint16_t(void** state){
	uint16_t value = 25652;
	uint16_t resultat = reverse_endianess_uint16_t(value);
	assert_int_equal(resultat, 0x3464);
	(void) state;
}

void test_reverse_endianess_uint32_t(void** state){
	uint32_t value = 1630889012;
	uint32_t resultat = reverse_endianess_uint32_t(value);
	assert_int_equal(resultat, 0x34643561);
	(void) state;
}

void test_reverse_endianess_uint64_t(void** state){
	uint64_t value = 3472328335704810548;
	uint64_t resultat = reverse_endianess_uint64_t(value);
	assert_int_equal(resultat, 0x3464356139303030);
	(void) state;
}

void test_readByte(void** state){
	FILE* pefile = fopen("../tests/testFiles/pe32+-notepad++.exe", "rb");
	if(pefile == NULL){
		perror("Failed to open file. Verify whether the file exists or not.\n");
	}

	size_t fReadSuccess;
	uint8_t* BYTE_Buffer = calloc(1, sizeof(uint8_t));
    if(fseek(pefile, (long) 0, SEEK_SET))
       perror("FATAL ERROR: Failed to seek to the specified file offset"); 
    else{
        fReadSuccess = fread(BYTE_Buffer, 0x01, 0x01, pefile); //buffer, size, count, stream
        if(fReadSuccess == 0x01)
            assert_int_equal(*BYTE_Buffer, 0x4d);
        else
            perror("FATAL ERROR: Failed to read appropriate countOfObjects in readByte");
    }

	free(BYTE_Buffer);

	(void) state;
}

void test_readWord(void** state){
	FILE* pefile = fopen("../tests/testFiles/pe32+-notepad++.exe", "rb");
	if(pefile == NULL){
		perror("Failed to open file. Verify whether the file exists or not.\n");
	}

	size_t fReadSuccess;
	uint16_t* WORD_Buffer = calloc(2, sizeof(uint8_t));
    if(fseek(pefile, (long) 0, SEEK_SET))
       perror("FATAL ERROR: Failed to seek to the specified file offset"); 
    else{
        fReadSuccess = fread(WORD_Buffer, 0x01, 0x02, pefile); //buffer, size, count, stream
        if(fReadSuccess == 0x02)
            assert_int_equal(*WORD_Buffer, 0x5a4d);
        else
            perror("FATAL ERROR: Failed to read appropriate countOfObjects in readByte");
    }

	free(WORD_Buffer);

	(void) state;
}


void test_readDWord(void** state){
	FILE* pefile = fopen("../tests/testFiles/pe32+-notepad++.exe", "rb");
	if(pefile == NULL){
		perror("Failed to open file. Verify whether the file exists or not.\n");
	}

	size_t fReadSuccess;
	uint32_t* DWORD_Buffer = calloc(4, sizeof(uint8_t));
    if(fseek(pefile, (long) 0, SEEK_SET))
       perror("FATAL ERROR: Failed to seek to the specified file offset"); 
    else{
        fReadSuccess = fread(DWORD_Buffer, 0x01, 0x04, pefile); //buffer, size, count, stream
        if(fReadSuccess == 0x04)
            assert_int_equal(*DWORD_Buffer, 0x905a4d);
        else
            perror("FATAL ERROR: Failed to read appropriate countOfObjects in readDWord");
    }

	free(DWORD_Buffer);
    (void) state;
}


void test_readQWord(void** state){
	FILE* pefile = fopen("../tests/testFiles/pe32+-notepad++.exe", "rb");
	if(pefile == NULL){
		perror("Failed to open file. Verify whether the file exists or not.\n");
	}

	size_t fReadSuccess;
	uint64_t* QWORD_Buffer = calloc(8, sizeof(uint8_t));
    if(fseek(pefile, (long) 0, SEEK_SET))
       perror("FATAL ERROR: Failed to seek to the specified file offset"); 
    else{
        fReadSuccess = fread(QWORD_Buffer, 0x01, 0x08, pefile); //buffer, size, count, stream
        if(fReadSuccess == 0x08)
            assert_int_equal(*QWORD_Buffer, 0x300905a4d);
        else
            perror("FATAL ERROR: Failed to read appropriate countOfObjects in readDWord");
    }

	free(QWORD_Buffer);
    (void) state;
}

void test_convert_WORD_To_uint16_t(void** state){
	uint16_t structureValue = 0x45;
	uint16_t convertedStructureValue = (uint16_t)((structureValue&15)*256 + ((structureValue>>4)&15)*4096 + (((structureValue>>8)&15)*1) + ((structureValue>>12)&15)*16);
    assert_int_equal(convertedStructureValue, 17664);
	(void) state;
}

void test_convert_DWORD_To_uint32_t(void** state){
	uint32_t structureValue = 0x4d5a0000;
	uint32_t convertedStructureValue = (((structureValue&255)&15)*16777216) + (((structureValue&255)>>4)*268435456) + ((((structureValue>>8)&255)&15)*65536) + ((((structureValue>>8)&255)>>4)*1048576) + (((structureValue>>16)&15)*256) + ((((structureValue>>16)&255)>>4)*4096) + (((structureValue>>24)&15)*1) + (((structureValue>>24)>>4)*16);
    assert_int_equal(convertedStructureValue, 23117);
	(void) state;
}

void test_hexdigit2int(void** state){
	unsigned char xd = '2';
	if (xd <= '9')
    	assert_in_range(xd - '0', 0, 9);

  	xd = (unsigned char) tolower(xd);
  	if (xd == 'a')
    	assert_int_equal(xd - 'a' + 10,10);
  	if (xd == 'b')
		assert_int_equal(xd - 'b' + 11,11);
  	if (xd == 'c')
    	assert_int_equal(xd - 'c' + 12,12);
  	if (xd == 'd')
    	assert_int_equal(xd - 'd' + 13,13);
  	if (xd == 'e')
    	assert_int_equal(xd - 'd' + 14,14);
  	if (xd == 'f')
    	assert_int_equal(xd - 'e' + 15,15);

	(void) state;
}

void test_convert_uint64_t_ToString(void** state){
	uint64_t numericalValue = 199252604001;
	char* computedString = malloc(18 * sizeof(char));
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
    assert_string_equal(computedString, ".data");
	free(computedString);
	(void) state;
}

void test_convertRelativeAddressToDiskOffset(void** state){
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
	}sectionHeader;

	sectionHeader.virtualSize = 0x12a3700;
	sectionHeader.virtualAddress = 0x100000;
	sectionHeader.sizeOfRawData = 0x2c3700;
	sectionHeader.pointerToRawData = 0x40000;
	sectionHeader.pointerToRelocations = 0x0000;
	sectionHeader.pointerToLineNumbers = 0x0000;
	sectionHeader.numberOfRelocations = 0x00;
	sectionHeader.numberOfLineNumbers = 0x00;
	sectionHeader.characteristics = 0x20000060;

	size_t i=0, numberOfSections=5;
	uint32_t relativeAddress = reverse_endianess_uint32_t(0x418010);

    for(i=0; i<numberOfSections; i++){
        uint32_t sectionHeaderVirtualAddress = (((sectionHeader.virtualAddress&255)&15)*16777216) + (((sectionHeader.virtualAddress&255)>>4)*268435456) + ((((sectionHeader.virtualAddress>>8)&255)&15)*65536) + ((((sectionHeader.virtualAddress>>8)&255)>>4)*1048576) + (((sectionHeader.virtualAddress>>16)&15)*256) + ((((sectionHeader.virtualAddress>>16)&255)>>4)*4096) + (((sectionHeader.virtualAddress>>24)&15)*1) + (((sectionHeader.virtualAddress>>24)>>4)*16);
        uint32_t sectionHeaderPointerToRawData = (((sectionHeader.pointerToRawData&255)&15)*16777216) + (((sectionHeader.pointerToRawData&255)>>4)*268435456) + ((((sectionHeader.pointerToRawData>>8)&255)&15)*65536) + ((((sectionHeader.pointerToRawData>>8)&255)>>4)*1048576) + (((sectionHeader.pointerToRawData>>16)&15)*256) + ((((sectionHeader.pointerToRawData>>16)&255)>>4)*4096) + (((sectionHeader.pointerToRawData>>24)&15)*1) + (((sectionHeader.pointerToRawData>>24)>>4)*16);
        uint32_t sectionHeaderSizeOfRawData = (((sectionHeader.sizeOfRawData&255)&15)*16777216) + (((sectionHeader.sizeOfRawData&255)>>4)*268435456) + ((((sectionHeader.sizeOfRawData>>8)&255)&15)*65536) + ((((sectionHeader.sizeOfRawData>>8)&255)>>4)*1048576) + (((sectionHeader.sizeOfRawData>>16)&15)*256) + ((((sectionHeader.sizeOfRawData>>16)&255)>>4)*4096) + (((sectionHeader.sizeOfRawData>>24)&15)*1) + (((sectionHeader.sizeOfRawData>>24)>>4)*16);
        
        if((relativeAddress >= sectionHeaderVirtualAddress) && (relativeAddress <= (sectionHeaderVirtualAddress + sectionHeaderSizeOfRawData))){
            assert_int_equal((uint32_t)(sectionHeaderPointerToRawData + relativeAddress - sectionHeaderVirtualAddress), 0x417010);
        }
    }

    (void) state;
}