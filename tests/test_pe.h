void test_initializeMSDOSHeader(void** state);
void test_initializeCoffHeader(void** state);
void test_initializeSectionHeader(void** state);
void test_initializeException(void** state);
void test_initializeBaseReloc(void** state);
void test_initializeDebug(void** state);
void test_initializeBoundImport(void** state);

void test_parseMSDOSHeader(void** state);
void test_parseCoffHeader(void** state);
void test_parseSectionHeaders(void** state);

void test_computeMD5Hash(void** state);
void test_computeSHA1Hash(void** state);
void test_computeSHA256Hash(void** state);