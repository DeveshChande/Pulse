#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "pe.h"

struct switchList{
    bool fileSpecified;
    char* pathOfFileSpecified;
    bool directorySpecified;
    char* pathOfDirectorySpecified;
    bool exportResult;
} globalSwitchList;


int main(int argc, char* argv[]){
    clock_t t = clock();

    for(int argCount = 1; argCount < argc; argCount+=2){
        if(!strcmp(argv[argCount], "-f")){
            globalSwitchList.fileSpecified = true;
            globalSwitchList.pathOfFileSpecified = argv[argCount+1];
        }
    }

    if(globalSwitchList.fileSpecified){
        parsePE(globalSwitchList.pathOfFileSpecified, globalSwitchList.exportResult);
    }

    t = clock() - t;
    double time_taken = ((double)t)/CLOCKS_PER_SEC;
    printf("\n\nParsing took %f seconds to execute.\n", time_taken);
    return 0;    
}