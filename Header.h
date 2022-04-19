struct PE {
	DWORD sizeDosHeader;
	DWORD sizeDosStub;
	DWORD sizeNTHeader32;
	DWORD sizeNTHeader64;
	DWORD sizeSectionHeader;
	DWORD sizeSections;

	IMAGE_DOS_HEADER dosHeader;
	char* DOS_STUB;
	IMAGE_NT_HEADERS32 ntHeader32;
	IMAGE_NT_HEADERS64 ntHeader64;
	IMAGE_SECTION_HEADER* sectionHeader;
	char** sections;
};

BOOL PEValidate(IMAGE_DOS_HEADER* dosHeader);
VOID getFileData(char* fileName, LPVOID* fileData, LPDWORD fileSize);
VOID Error(char* ErrorMessage, BOOL printErrorCode, BOOL isReturn, int exitCode);
DWORD64 RVAToOffset(DWORD64 RVA, IMAGE_DOS_HEADER* dosHeader);
DWORD64 OffsetToRVA(DWORD64 Offset, IMAGE_DOS_HEADER* dosHeader);
VOID printDosHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printNtHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printNtSignature(IMAGE_DOS_HEADER* dosHeader);
VOID printFileHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printOptionalHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printDataDirectory(IMAGE_DOS_HEADER* dosHeader);
VOID printSectionHeaders(IMAGE_DOS_HEADER* dosHeader);
VOID printExportSection(IMAGE_DOS_HEADER* dosHeader, BOOL printFunction);
VOID printImportSection(IMAGE_DOS_HEADER* dosHeader, BOOL printFunction);
BOOL is64(IMAGE_DOS_HEADER* dosHeader);
PE parsePEFile(IMAGE_DOS_HEADER* dosHeader);
VOID writeBinary(PE pe, char* fileName, DWORD size);
