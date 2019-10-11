#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    size_t size;
    uint8_t *content;
} PseudoFatArray;

PseudoFatArray readFile(char *fileName) {
    FILE *file;
    PseudoFatArray ret;
    
    file = fopen(fileName, "rb");
    if (file == NULL) {
        printf("Can't open file \"%s\"", fileName);
        exit(-1);
    }
    fseek(file, 0, SEEK_END);
    ret.size = ftell(file);
    rewind(file);
    ret.content = malloc(ret.size);
    if (ret.content == NULL) {
        printf("Can't allocate %lu bytes of memory to load input file", (unsigned long)ret.size);
        exit(-1);
    }
    fread(ret.content, ret.size, 1, file);
    fclose(file);
    return ret;
}

void writeFile(char *fileName, PseudoFatArray data) {
    FILE *file = fopen(fileName, "wb");
    fwrite(data.content, data.size, 1, file);
    fclose(file);
}

void incorrectFile(char *moreInfo) {
    puts("Oops! Looks like the file is incorrect...");
    puts(moreInfo);
    exit(-1);
}

int main(int argc, char **argv) {
    PseudoFatArray cflf;
    uint32_t peSignatureOffset;
    const int sizeOfPeSignature = 4;
    const int sizeOfCoffFileHeader = 20;
    uint32_t optionalHeaderOffset;
    uint16_t optionalHeaderMagic;
    size_t offsetOfSubsystemInOptionalHeader;
    size_t offsetOfSubsystemInFile;
    uint16_t subsystem;
    char *outputFileName;

    if (argc < 2 || argc > 3) {
        puts("Usage: GUIficator *inputExecutableFileName* [*outputExecutableFileName*]");
        exit(-1);
    }
    cflf = readFile(argv[1]);
    if (cflf.size < 0x3c + sizeof(peSignatureOffset)) {
        incorrectFile("Can't access PE signature's offset in MZ header");
    }
    peSignatureOffset = *(uint32_t *)&cflf.content[0x3c];
    optionalHeaderOffset = peSignatureOffset + sizeOfPeSignature + sizeOfCoffFileHeader;
    if (cflf.size < optionalHeaderOffset + sizeof(optionalHeaderMagic)) {
        incorrectFile("Can't access PE optional header");
    }
    optionalHeaderMagic = *(uint16_t *)&cflf.content[optionalHeaderOffset];
    if (optionalHeaderMagic == 0x10b || optionalHeaderMagic == 0x20b) {
        offsetOfSubsystemInOptionalHeader = 68;
    } else {
        incorrectFile("Optional header's Magic has invalid value (not 0x10b (PE32) and not 0x20b (PE32+))");
    }
    offsetOfSubsystemInFile = optionalHeaderOffset + offsetOfSubsystemInOptionalHeader;
    if (cflf.size < offsetOfSubsystemInFile + sizeof(subsystem)) {
        incorrectFile("Can't access Subsystem field");
    }
    subsystem = *(uint16_t *)&cflf.content[offsetOfSubsystemInFile];
    printf("Old subsystem: %d, will be set to 2 (aka IMAGE_SUBSYSTEM_WINDOWS_GUI)", subsystem);
    *(uint16_t *)&cflf.content[offsetOfSubsystemInFile] = 2;
    outputFileName = argc == 3 ? argv[2] : argv[1];
    writeFile(outputFileName, cflf);
}

