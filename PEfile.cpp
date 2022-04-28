#include "Header.h"


int main(int argc, char* argv[]) {
	LPVOID fileData = NULL;
	IMAGE_DOS_HEADER* dosHeader = NULL;
	DWORD fileSize = 0;

	if (argc != 2)
		Error("Usage: PEfile <PE file>", FALSE, TRUE, 1);

	getFileData(argv[1], &fileData, &fileSize);
	if (!PEValidate(fileData)) {
		Error("Invalid file.", TRUE, TRUE, 1);
	}

	//printf("DOS_HEADER\n");
	//printDosHeader(dosHeader);
	//printf("PE_HEADER\n");
	//printNtHeader(dosHeader);
	//printf("DATA_DIRECTORY\n");
	//printDataDirectory(dosHeader);
	//printf("SECTION_HEADERS\n");
	//printSectionHeaders(dosHeader);
	//printf("EXPORT\n");
	//printExportSection(dosHeader, TRUE);
	//printf("IMPORT\n");
	//printImportSection(dosHeader, TRUE);

	PE pe = parsePEFile(fileData);
	if (isExecutable(fileData)) {
		//writeBinary(pe, "output.exe", fileSize);
		char xcode[] = "\x6A\x00\x6A\x00\x68\x6A\x00\xFF\x15\xB8";
		Inject(fileData, fileSize, xcode, sizeof(xcode), "output.exe");
	}
	return 0;
}

