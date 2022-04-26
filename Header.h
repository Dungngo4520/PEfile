#include <stdio.h>
#include <Windows.h>

struct PE {
	DWORD sizeDosHeader;
	DWORD sizeDosStub;
	DWORD sizeNTHeader32;
	DWORD sizeNTHeader64;
	DWORD sizeSectionHeader;
	DWORD sizeSections;

	IMAGE_DOS_HEADER dosHeader;
	char* dosStub;
	IMAGE_NT_HEADERS32 ntHeader32;
	IMAGE_NT_HEADERS64 ntHeader64;
	IMAGE_SECTION_HEADER* sectionHeader;
	char** sections;
};

BOOL PEValidate(LPVOID fileData);
VOID getFileData(char* fileName, LPVOID* fileData, LPDWORD fileSize);
VOID Error(char* ErrorMessage, BOOL printErrorCode, BOOL isReturn, int exitCode);
DWORD64 RVAToOffset(DWORD64 RVA, LPVOID fileData);
DWORD64 OffsetToRVA(DWORD64 Offset, LPVOID fileData);
VOID printDosHeader(LPVOID fileData);
VOID printNtHeader(LPVOID fileData);
VOID printNtSignature(LPVOID fileData);
VOID printFileHeader(LPVOID fileData);
VOID printOptionalHeader(LPVOID fileData);
VOID printDataDirectory(LPVOID fileData);
VOID printSectionHeaders(LPVOID fileData);
VOID printExportSection(LPVOID fileData, BOOL printFunction);
VOID printImportSection(LPVOID fileData, BOOL printFunction);
BOOL is64(LPVOID fileData);
BOOL isExecutable(LPVOID fileData);
PE parsePEFile(LPVOID fileData);
VOID writeBinary(PE pe, char* fileName, DWORD size);
DWORD64 align(DWORD64 address, DWORD64 alignment);
VOID Inject(LPVOID fileData, DWORD size, char* code, DWORD codeSize, char* outPath);