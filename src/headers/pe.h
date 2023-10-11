extern uint8_t reverse_endianess_uint8_t(uint8_t value);
extern uint16_t reverse_endianess_uint16_t(uint16_t value);
extern uint32_t reverse_endianess_uint32_t(uint32_t value);
extern uint64_t reverse_endianess_uint64_t(uint64_t value);
extern uint8_t readByte(FILE* pefile, size_t offset, uint8_t* buffer);
extern uint16_t readWord(FILE* pefile, size_t offset, uint16_t* buffer);
extern uint32_t readDWord(FILE* pefile, size_t offset, uint32_t* buffer);
extern uint64_t readQWord(FILE* pefile, size_t offset, uint64_t* buffer);

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
