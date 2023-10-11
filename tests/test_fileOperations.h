#include "../src/headers/pe.h"

void test_reverse_endianess_uint8_t(void** state);
void test_reverse_endianess_uint16_t(void** state);
void test_reverse_endianess_uint32_t(void** state);
void test_reverse_endianess_uint64_t(void** state);
void test_readByte(void** state);
void test_readWord(void** state);
void test_readDWord(void** state);
void test_readQWord(void** state);
void test_convert_WORD_To_uint16_t(void** state);
void test_convert_DWORD_To_uint32_t(void** state);
void test_hexdigit2int(void** state);
void test_convert_uint64_t_ToString(void** state);
void test_convertRelativeAddressToDiskOffset(void** state);

void test_reverse_endianess_uint8(void** state){
	uint8_t value = 52;
	uint8_t resultat = reverse_endianess_uint8_t(value);
	assert_int_equal(resultat, 0x34);
	(void) state;
}

void test_reverse_endianess_uint16(void** state){
	uint16_t value = 25652;
	uint16_t resultat = reverse_endianess_uint16_t(value);
	assert_int_equal(resultat, 0x3464);
	(void) state;
}

void test_reverse_endianess_uint32(void** state){
	uint32_t value = 1630889012;
	uint32_t resultat = reverse_endianess_uint32_t(value);
	assert_int_equal(resultat, 0x34643561);
	(void) state;
}

void test_reverse_endianess_uint64(void** state){
	uint64_t value = 3472328335704810548;
	uint64_t resultat = reverse_endianess_uint64_t(value);
	assert_int_equal(resultat, 0x3464356139303030);
	(void) state;
}
