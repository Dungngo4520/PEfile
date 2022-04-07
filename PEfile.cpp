#include <stdio.h>
#include <Windows.h>



void Error(char* ErrorMessage, BOOL printErrorCode, BOOL isReturn, int exitCode);
DWORD RVAToOffset32(DWORD RVA, IMAGE_DOS_HEADER* dosHeader);
DWORD64 RVAToOffset64(DWORD64 RVA, IMAGE_DOS_HEADER* dosHeader);
DWORD OffsetToRVA32(DWORD Offset, IMAGE_DOS_HEADER* dosHeader);
DWORD64 OffsetToRVA64(DWORD64 Offset, IMAGE_DOS_HEADER* dosHeader);
void printDosHeader(IMAGE_DOS_HEADER* dosHeader);
void printNtHeader(IMAGE_DOS_HEADER* dosHeader);
void printNtSignature(IMAGE_DOS_HEADER* dosHeader);
void printFileHeader(IMAGE_DOS_HEADER* dosHeader);
void printOptionalHeader(IMAGE_DOS_HEADER* dosHeader);
void printDataDirectory(IMAGE_DOS_HEADER* dosHeader);
void printSectionHeaders(IMAGE_DOS_HEADER* dosHeader);
void printExportSection(IMAGE_DOS_HEADER* dosHeader, BOOL printFunction);
void printImportSection(IMAGE_DOS_HEADER* dosHeader, BOOL printFunction);

int main(int argc, char* argv[]) {
	enum OS { x86, x64, Neither };
	char fileName[MAX_PATH] = { 0 };
	HANDLE hFile = NULL;
	OS machine = Neither;
	DWORD fileSize = 0;
	DWORD byteRead = 0;
	LPVOID fileData = NULL;
	IMAGE_DOS_HEADER* dosHeader;
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_NT_HEADERS32* ntHeader32;
	IMAGE_NT_HEADERS64* ntHeader64;
	IMAGE_FILE_HEADER fileHeader;
	IMAGE_OPTIONAL_HEADER optionalHeader;
	IMAGE_OPTIONAL_HEADER32 optionalHeader32;
	IMAGE_OPTIONAL_HEADER64 optionalHeader64;
	IMAGE_DATA_DIRECTORY* dataDirectory;
	IMAGE_SECTION_HEADER* sectionHeader;
	IMAGE_EXPORT_DIRECTORY* exportDirectory;
	IMAGE_IMPORT_DESCRIPTOR* importDirectory;

	if (argc != 2)
		Error("Usage: PEfile <PE file>", FALSE, TRUE, 1);

	strcpy_s(fileName, MAX_PATH, argv[1]);
	hFile = CreateFile(fileName, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		Error("Cannot open file.", TRUE, TRUE, 1);

	fileSize = GetFileSize(hFile, NULL);

	fileData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
	if (!fileData)
		Error("Cannot allocate memory.", FALSE, TRUE, 1);
	if (!ReadFile(hFile, fileData, fileSize, &byteRead, NULL))
		Error("Cannot read file.", TRUE, TRUE, 1);

	dosHeader = (IMAGE_DOS_HEADER*)fileData;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		Error("Not DOS-compatible file\n", FALSE, TRUE, 1);
	}

	ntHeader = (IMAGE_NT_HEADERS*)((DWORD_PTR)dosHeader + dosHeader->e_lfanew);
	ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);

	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		Error("Not PE file.", FALSE, TRUE, 1);
	}

	if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		machine = x86;
		fileHeader = ntHeader32->FileHeader;
		optionalHeader32 = ntHeader32->OptionalHeader;
		dataDirectory = optionalHeader32.DataDirectory;
		printf("%x",(DWORD)(&ntHeader32->FileHeader.Machine)- (DWORD)dosHeader);
	}
	else if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		machine = x64;
		fileHeader = ntHeader64->FileHeader;
		optionalHeader64 = ntHeader64->OptionalHeader;
		dataDirectory = optionalHeader64.DataDirectory;
		printf("%x", (DWORD64)(&ntHeader32->FileHeader.Machine) - (DWORD64)dosHeader);
	}
	else {
		machine = Neither;
		fileHeader = ntHeader->FileHeader;
		optionalHeader = ntHeader->OptionalHeader;
		dataDirectory = optionalHeader.DataDirectory;
	}

	printf("DOS_HEADER\n");
	printDosHeader(dosHeader);
	printf("PE_HEADER\n");
	printNtHeader(dosHeader);
	printf("DATA_DIRECTORY\n");
	printDataDirectory(dosHeader);
	printf("SECTION_HEADERS\n");
	printSectionHeaders(dosHeader);
	printf("EXPORT\n");
	printExportSection(dosHeader, TRUE);
	printf("IMPORT\n");
	printImportSection(dosHeader, TRUE);
	return 0;
}

void Error(char* ErrorMessage, BOOL printErrorCode, BOOL isReturn, int exitCode) {
	printf(ErrorMessage);
	if (printErrorCode)
		printf("\nError: %d\n", GetLastError());
	if (isReturn)
		ExitProcess(exitCode);
}

DWORD RVAToOffset32(DWORD RVA, IMAGE_DOS_HEADER* dosHeader) {
	IMAGE_SECTION_HEADER* sectionHeader;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD)dosHeader + dosHeader->e_lfanew);

	sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD)ntHeader32 + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + ntHeader32->FileHeader.SizeOfOptionalHeader);
	if (RVA == 0)return 0;
	for (int i = 0; i < ntHeader32->FileHeader.NumberOfSections; i++) {
		if (RVA >= sectionHeader[i].VirtualAddress && RVA < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
			return RVA - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData;
		}
	}
	return 0;
}
DWORD64 RVAToOffset64(DWORD64 RVA, IMAGE_DOS_HEADER* dosHeader) {
	IMAGE_SECTION_HEADER* sectionHeader;
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);

	sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD64)ntHeader64 + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + ntHeader64->FileHeader.SizeOfOptionalHeader);
	if (RVA == 0)return 0;
	for (int i = 0; i < ntHeader64->FileHeader.NumberOfSections; i++) {
		if (RVA >= sectionHeader[i].VirtualAddress && RVA < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
			return RVA - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData;
		}
	}
	return 0;
}
DWORD OffsetToRVA32(DWORD Offset, IMAGE_DOS_HEADER* dosHeader) {
	IMAGE_SECTION_HEADER* sectionHeader;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD)dosHeader + dosHeader->e_lfanew);

	sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD)ntHeader32 + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + ntHeader32->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < ntHeader32->FileHeader.NumberOfSections; i++) {
		if (Offset >= sectionHeader[i].PointerToRawData && Offset < sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData) {
			return Offset - sectionHeader[i].PointerToRawData + sectionHeader[i].VirtualAddress;
		}
	}
	return 0;
}
DWORD64 OffsetToRVA64(DWORD64 Offset, IMAGE_DOS_HEADER* dosHeader) {
	IMAGE_SECTION_HEADER* sectionHeader;
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);

	sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD64)ntHeader64 + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + ntHeader64->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < ntHeader64->FileHeader.NumberOfSections; i++) {
		if (Offset >= sectionHeader[i].PointerToRawData && Offset < sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData) {
			return Offset - sectionHeader[i].PointerToRawData + sectionHeader[i].VirtualAddress;
		}
	}
	return 0;
}

void printDosHeader(IMAGE_DOS_HEADER* dosHeader) {
	printf("%-40s|0x%-8x|%d\n", "  e_cblp", dosHeader->e_cblp, dosHeader->e_cblp);
	printf("%-40s|0x%-8x|%d\n", "  e_cp", dosHeader->e_cp, dosHeader->e_cp);
	printf("%-40s|0x%-8x|%d\n", "  e_cparhdr", dosHeader->e_cparhdr, dosHeader->e_cparhdr);
	printf("%-40s|0x%-8x|%d\n", "  e_crlc", dosHeader->e_crlc, dosHeader->e_crlc);
	printf("%-40s|0x%-8x|%d\n", "  e_cs", dosHeader->e_cs, dosHeader->e_cs);
	printf("%-40s|0x%-8x|%d\n", "  e_csum", dosHeader->e_csum, dosHeader->e_csum);
	printf("%-40s|0x%-8x|%d\n", "  e_ip", dosHeader->e_ip, dosHeader->e_ip);
	printf("%-40s|0x%-8x|%d\n", "  e_lfanew", dosHeader->e_lfanew, dosHeader->e_lfanew);
	printf("%-40s|0x%-8x|%d\n", "  e_lfarlc", dosHeader->e_lfarlc, dosHeader->e_lfarlc);
	printf("%-40s|0x%-8x|%d\n", "  e_magic", dosHeader->e_magic, dosHeader->e_magic);
	printf("%-40s|0x%-8x|%d\n", "  e_maxalloc", dosHeader->e_maxalloc, dosHeader->e_maxalloc);
	printf("%-40s|0x%-8x|%d\n", "  e_minalloc", dosHeader->e_minalloc, dosHeader->e_minalloc);
	printf("%-40s|0x%-8x|%d\n", "  e_oemid", dosHeader->e_oemid, dosHeader->e_oemid);
	printf("%-40s|0x%-8x|%d\n", "  e_oeminfo", dosHeader->e_oeminfo, dosHeader->e_oeminfo);
	printf("%-40s|0x%-8x|%d\n", "  e_ovno", dosHeader->e_ovno, dosHeader->e_ovno);
	printf("%-40s|0x%-8x|%d\n", "  e_res", dosHeader->e_res, dosHeader->e_res);
	printf("%-40s|0x%-8x|%d\n", "  e_res2", dosHeader->e_res2, dosHeader->e_res2);
	printf("%-40s|0x%-8x|%d\n", "  e_sp", dosHeader->e_sp, dosHeader->e_sp);
	printf("%-40s|0x%-8x|%d\n", "  e_ss", dosHeader->e_ss, dosHeader->e_ss);
}

void printNtHeader(IMAGE_DOS_HEADER* dosHeader) {
	printNtSignature(dosHeader);
	printFileHeader(dosHeader);
	printOptionalHeader(dosHeader);
}

void printNtSignature(IMAGE_DOS_HEADER* dosHeader) {
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);

	if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("%-40s|0x%-8x|%d\n", "  Signature", ntHeader32->Signature, ntHeader32->Signature);
	}
	else if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		printf("%-40s|0x%-8x|%d\n", "  Signature", ntHeader64->Signature, ntHeader64->Signature);
	}
	else return;
}

void printFileHeader(IMAGE_DOS_HEADER* dosHeader) {
	IMAGE_FILE_HEADER fileHeader;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);

	if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		fileHeader = ntHeader32->FileHeader;
	}
	else if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		fileHeader = ntHeader64->FileHeader;
	}
	else return;
	printf("%-40s|0x%-8x|%d\n", "  FileHeader", fileHeader, fileHeader);
	printf("%-40s|0x%-8x|%d\n", "    Characteristics", fileHeader.Characteristics, fileHeader.Characteristics);
	printf("%-40s|0x%-8x|%d\n", "    Machine", fileHeader.Machine, fileHeader.Machine);
	printf("%-40s|0x%-8x|%d\n", "    NumberOfSections", fileHeader.NumberOfSections, fileHeader.NumberOfSections);
	printf("%-40s|0x%-8x|%d\n", "    NumberOfSymbols", fileHeader.NumberOfSymbols, fileHeader.NumberOfSymbols);
	printf("%-40s|0x%-8x|%d\n", "    PointerToSymbolTable", fileHeader.PointerToSymbolTable, fileHeader.PointerToSymbolTable);
	printf("%-40s|0x%-8x|%d\n", "    SizeOfOptionalHeader", fileHeader.SizeOfOptionalHeader, fileHeader.SizeOfOptionalHeader);
	printf("%-40s|0x%-8x|%d\n", "    TimeDateStamp", fileHeader.TimeDateStamp, fileHeader.TimeDateStamp);
}

void printOptionalHeader(IMAGE_DOS_HEADER* dosHeader) {
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);

	if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		IMAGE_OPTIONAL_HEADER32 optionalHeader = ntHeader32->OptionalHeader;
		printf("%-40s|0x%-8x|%d\n", "  OptionalHeader", optionalHeader, optionalHeader);
		printf("%-40s|0x%-8x|%d\n", "    AddressOfEntryPoint", optionalHeader.AddressOfEntryPoint, optionalHeader.AddressOfEntryPoint);
		printf("%-40s|0x%-8x|%d\n", "    BaseOfCode", optionalHeader.BaseOfCode, optionalHeader.BaseOfCode);
		printf("%-40s|0x%-8x|%d\n", "    BaseOfData", optionalHeader.BaseOfData, optionalHeader.BaseOfData);
		printf("%-40s|0x%-8x|%d\n", "    CheckSum", optionalHeader.CheckSum, optionalHeader.CheckSum);
		printf("%-40s|0x%-8x|%d\n", "    DataDirectory", optionalHeader.DataDirectory, optionalHeader.DataDirectory);
		printf("%-40s|0x%-8x|%d\n", "    DllCharacteristics", optionalHeader.DllCharacteristics, optionalHeader.DllCharacteristics);
		printf("%-40s|0x%-8x|%d\n", "    FileAlignment", optionalHeader.FileAlignment, optionalHeader.FileAlignment);
		printf("%-40s|0x%-8x|%d\n", "    ImageBase", optionalHeader.ImageBase, optionalHeader.ImageBase);
		printf("%-40s|0x%-8x|%d\n", "    LoaderFlags", optionalHeader.LoaderFlags, optionalHeader.LoaderFlags);
		printf("%-40s|0x%-8x|%d\n", "    Magic", optionalHeader.Magic, optionalHeader.Magic);
		printf("%-40s|0x%-8x|%d\n", "    MajorImageVersion", optionalHeader.MajorImageVersion, optionalHeader.MajorImageVersion);
		printf("%-40s|0x%-8x|%d\n", "    MajorLinkerVersion", optionalHeader.MajorLinkerVersion, optionalHeader.MajorLinkerVersion);
		printf("%-40s|0x%-8x|%d\n", "    MajorOperatingSystemVersion", optionalHeader.MajorOperatingSystemVersion, optionalHeader.MajorOperatingSystemVersion);
		printf("%-40s|0x%-8x|%d\n", "    MajorSubsystemVersion", optionalHeader.MajorSubsystemVersion, optionalHeader.MajorSubsystemVersion);
		printf("%-40s|0x%-8x|%d\n", "    MinorImageVersion", optionalHeader.MinorImageVersion, optionalHeader.MinorImageVersion);
		printf("%-40s|0x%-8x|%d\n", "    MinorSubsystemVersion", optionalHeader.MinorSubsystemVersion, optionalHeader.MinorSubsystemVersion);
		printf("%-40s|0x%-8x|%d\n", "    NumberOfRvaAndSizes", optionalHeader.NumberOfRvaAndSizes, optionalHeader.NumberOfRvaAndSizes);
		printf("%-40s|0x%-8x|%d\n", "    SectionAlignment", optionalHeader.SectionAlignment, optionalHeader.SectionAlignment);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfCode", optionalHeader.SizeOfCode, optionalHeader.SizeOfCode);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfHeaders", optionalHeader.SizeOfHeaders, optionalHeader.SizeOfHeaders);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfHeapCommit", optionalHeader.SizeOfHeapCommit, optionalHeader.SizeOfHeapCommit);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfHeapReserve", optionalHeader.SizeOfHeapReserve, optionalHeader.SizeOfHeapReserve);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfImage", optionalHeader.SizeOfImage, optionalHeader.SizeOfImage);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfInitializedData", optionalHeader.SizeOfInitializedData, optionalHeader.SizeOfInitializedData);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfStackCommit", optionalHeader.SizeOfStackCommit, optionalHeader.SizeOfStackCommit);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfStackReserve", optionalHeader.SizeOfStackReserve, optionalHeader.SizeOfStackReserve);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfUninitializedData", optionalHeader.SizeOfUninitializedData, optionalHeader.SizeOfUninitializedData);
		printf("%-40s|0x%-8x|%d\n", "    Subsystem", optionalHeader.Subsystem, optionalHeader.Subsystem);
		printf("%-40s|0x%-8x|%d\n", "    Win32VersionValue", optionalHeader.Win32VersionValue, optionalHeader.Win32VersionValue);
	}
	else if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		IMAGE_OPTIONAL_HEADER64 optionalHeader = ntHeader64->OptionalHeader;
		printf("%-40s|0x%-8x|%d\n", "  OptionalHeader", optionalHeader, optionalHeader);
		printf("%-40s|0x%-8x|%d\n", "    AddressOfEntryPoint", optionalHeader.AddressOfEntryPoint, optionalHeader.AddressOfEntryPoint);
		printf("%-40s|0x%-8x|%d\n", "    BaseOfCode", optionalHeader.BaseOfCode, optionalHeader.BaseOfCode);
		//printf("%-40s|0x%-8x|%d\n", "    BaseOfData", optionalHeader.BaseOfData, optionalHeader.BaseOfData);
		printf("%-40s|0x%-8x|%d\n", "    CheckSum", optionalHeader.CheckSum, optionalHeader.CheckSum);
		printf("%-40s|0x%-8x|%d\n", "    DataDirectory", optionalHeader.DataDirectory, optionalHeader.DataDirectory);
		printf("%-40s|0x%-8x|%d\n", "    DllCharacteristics", optionalHeader.DllCharacteristics, optionalHeader.DllCharacteristics);
		printf("%-40s|0x%-8x|%d\n", "    FileAlignment", optionalHeader.FileAlignment, optionalHeader.FileAlignment);
		printf("%-40s|0x%-8x|%d\n", "    ImageBase", optionalHeader.ImageBase, optionalHeader.ImageBase);
		printf("%-40s|0x%-8x|%d\n", "    LoaderFlags", optionalHeader.LoaderFlags, optionalHeader.LoaderFlags);
		printf("%-40s|0x%-8x|%d\n", "    Magic", optionalHeader.Magic, optionalHeader.Magic);
		printf("%-40s|0x%-8x|%d\n", "    MajorImageVersion", optionalHeader.MajorImageVersion, optionalHeader.MajorImageVersion);
		printf("%-40s|0x%-8x|%d\n", "    MajorLinkerVersion", optionalHeader.MajorLinkerVersion, optionalHeader.MajorLinkerVersion);
		printf("%-40s|0x%-8x|%d\n", "    MajorOperatingSystemVersion", optionalHeader.MajorOperatingSystemVersion, optionalHeader.MajorOperatingSystemVersion);
		printf("%-40s|0x%-8x|%d\n", "    MajorSubsystemVersion", optionalHeader.MajorSubsystemVersion, optionalHeader.MajorSubsystemVersion);
		printf("%-40s|0x%-8x|%d\n", "    MinorImageVersion", optionalHeader.MinorImageVersion, optionalHeader.MinorImageVersion);
		printf("%-40s|0x%-8x|%d\n", "    MinorSubsystemVersion", optionalHeader.MinorSubsystemVersion, optionalHeader.MinorSubsystemVersion);
		printf("%-40s|0x%-8x|%d\n", "    NumberOfRvaAndSizes", optionalHeader.NumberOfRvaAndSizes, optionalHeader.NumberOfRvaAndSizes);
		printf("%-40s|0x%-8x|%d\n", "    SectionAlignment", optionalHeader.SectionAlignment, optionalHeader.SectionAlignment);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfCode", optionalHeader.SizeOfCode, optionalHeader.SizeOfCode);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfHeaders", optionalHeader.SizeOfHeaders, optionalHeader.SizeOfHeaders);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfHeapCommit", optionalHeader.SizeOfHeapCommit, optionalHeader.SizeOfHeapCommit);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfHeapReserve", optionalHeader.SizeOfHeapReserve, optionalHeader.SizeOfHeapReserve);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfImage", optionalHeader.SizeOfImage, optionalHeader.SizeOfImage);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfInitializedData", optionalHeader.SizeOfInitializedData, optionalHeader.SizeOfInitializedData);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfStackCommit", optionalHeader.SizeOfStackCommit, optionalHeader.SizeOfStackCommit);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfStackReserve", optionalHeader.SizeOfStackReserve, optionalHeader.SizeOfStackReserve);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfUninitializedData", optionalHeader.SizeOfUninitializedData, optionalHeader.SizeOfUninitializedData);
		printf("%-40s|0x%-8x|%d\n", "    Subsystem", optionalHeader.Subsystem, optionalHeader.Subsystem);
		printf("%-40s|0x%-8x|%d\n", "    Win32VersionValue", optionalHeader.Win32VersionValue, optionalHeader.Win32VersionValue);
	}
	else return;
}

void printDataDirectory(IMAGE_DOS_HEADER* dosHeader) {
	IMAGE_DATA_DIRECTORY* dataDirectory;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);

	if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		dataDirectory = ntHeader32->OptionalHeader.DataDirectory;
	}
	else if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		dataDirectory = ntHeader64->OptionalHeader.DataDirectory;
	}
	else return;
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_EXPORT", dataDirectory[0].VirtualAddress, dataDirectory[0].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_IMPORT", dataDirectory[1].VirtualAddress, dataDirectory[1].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_RESOURCE", dataDirectory[2].VirtualAddress, dataDirectory[2].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_EXCEPTION", dataDirectory[3].VirtualAddress, dataDirectory[3].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_SECURITY", dataDirectory[4].VirtualAddress, dataDirectory[4].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_BASERELOC", dataDirectory[5].VirtualAddress, dataDirectory[5].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_DEBUG", dataDirectory[6].VirtualAddress, dataDirectory[6].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_ARCHITECTURE", dataDirectory[7].VirtualAddress, dataDirectory[7].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_GLOBALPTR", dataDirectory[8].VirtualAddress, dataDirectory[8].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_TLS", dataDirectory[9].VirtualAddress, dataDirectory[9].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", dataDirectory[10].VirtualAddress, dataDirectory[10].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", dataDirectory[11].VirtualAddress, dataDirectory[11].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_IAT", dataDirectory[12].VirtualAddress, dataDirectory[12].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", dataDirectory[13].VirtualAddress, dataDirectory[13].Size);
	printf("%-40s|0x%-8x|%d\n", "  IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", dataDirectory[14].VirtualAddress, dataDirectory[14].Size);
}

void printSectionHeaders(IMAGE_DOS_HEADER* dosHeader) {
	IMAGE_FILE_HEADER fileHeader;
	IMAGE_SECTION_HEADER* sectionHeader;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);

	if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		fileHeader = ntHeader32->FileHeader;
		sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD64)ntHeader32 + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader);
	}
	else if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		fileHeader = ntHeader64->FileHeader;
		sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD64)ntHeader64 + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader);
	}
	else return;

	for (int i = 0; i < fileHeader.NumberOfSections; i++) {
		printf("  %-40s\n", sectionHeader[i].Name, sectionHeader[i].Name);
		printf("%-40s|0x%-8x|%d\n", "    VirtualAddress", sectionHeader[i].VirtualAddress, sectionHeader[i].VirtualAddress);
		printf("%-40s|0x%-8x|%d\n", "    VirtualSize", sectionHeader[i].Misc.VirtualSize, sectionHeader[i].Misc.VirtualSize);
		printf("%-40s|0x%-8x|%d\n", "    Characteristics", sectionHeader[i].Characteristics, sectionHeader[i].Characteristics);
		printf("%-40s|0x%-8x|%d\n", "    PointerToRawData", sectionHeader[i].PointerToRawData, sectionHeader[i].PointerToRawData);
		printf("%-40s|0x%-8x|%d\n", "    PointerToRelocations", sectionHeader[i].PointerToRelocations, sectionHeader[i].PointerToRelocations);
		printf("%-40s|0x%-8x|%d\n", "    SizeOfRawData", sectionHeader[i].SizeOfRawData, sectionHeader[i].SizeOfRawData);
		printf("%-40s|0x%-8x|%d\n", "    NumberOfLinenumbers", sectionHeader[i].NumberOfLinenumbers, sectionHeader[i].NumberOfLinenumbers);
		printf("%-40s|0x%-8x|%d\n", "    PointerToLinenumbers", sectionHeader[i].PointerToLinenumbers, sectionHeader[i].PointerToLinenumbers);
	}
}

void printExportSection(IMAGE_DOS_HEADER * dosHeader, BOOL printFunction) {
	IMAGE_DATA_DIRECTORY* dataDirectory;
	IMAGE_EXPORT_DIRECTORY* exportDirectory;
	IMAGE_SECTION_HEADER sectionHeader;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);

	if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		dataDirectory = ntHeader32->OptionalHeader.DataDirectory;
		exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(RVAToOffset32(dataDirectory[0].VirtualAddress, dosHeader) + (DWORD)dosHeader);
	}
	else if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		dataDirectory = ntHeader64->OptionalHeader.DataDirectory;
		exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(RVAToOffset64(dataDirectory[0].VirtualAddress, dosHeader) + (DWORD64)dosHeader);
	}
	else return;
	if (dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0) {
		printf("%-40s|0x%-8x|%d\n", "  AddressOfFunctions", exportDirectory->AddressOfFunctions, exportDirectory->AddressOfFunctions);
		printf("%-40s|0x%-8x|%d\n", "  AddressOfNameOrdinals", exportDirectory->AddressOfNameOrdinals, exportDirectory->AddressOfNameOrdinals);
		printf("%-40s|0x%-8x|%d\n", "  AddressOfNames", exportDirectory->AddressOfNames, exportDirectory->AddressOfNames);
		printf("%-40s|0x%-8x|%d\n", "  Base", exportDirectory->Base, exportDirectory->Base);
		printf("%-40s|0x%-8x|%d\n", "  Characteristics", exportDirectory->Characteristics, exportDirectory->Characteristics);
		printf("%-40s|0x%-8x|%d\n", "  MajorVersion", exportDirectory->MajorVersion, exportDirectory->MajorVersion);
		printf("%-40s|0x%-8x|%d\n", "  MinorVersion", exportDirectory->MinorVersion, exportDirectory->MinorVersion);
		printf("%-40s|0x%-8x|%d\n", "  Name", exportDirectory->Name, exportDirectory->Name);
		printf("%-40s|0x%-8x|%d\n", "  NumberOfFunctions", exportDirectory->NumberOfFunctions, exportDirectory->NumberOfFunctions);
		printf("%-40s|0x%-8x|%d\n", "  NumberOfNames", exportDirectory->NumberOfNames, exportDirectory->NumberOfNames);
		printf("%-40s|0x%-8x|%d\n", "  TimeDateStamp", exportDirectory->TimeDateStamp, exportDirectory->TimeDateStamp);

		if (printFunction) {
			DWORD* addressFunction = (DWORD*)(RVAToOffset32(exportDirectory->AddressOfFunctions, dosHeader) + (DWORD)dosHeader);
			DWORD* addressName = (DWORD*)(RVAToOffset32(exportDirectory->AddressOfNames, dosHeader) + (DWORD)dosHeader);
			WORD* addressNameOrdinal = (WORD*)(RVAToOffset32(exportDirectory->AddressOfNameOrdinals, dosHeader) + (DWORD)dosHeader);

			printf("\n%-41s%-11s%-10s\n", "  EXPORT FUNCTION", "FuncRVA", "NameRVA");
			for (int i = 0; i < exportDirectory->NumberOfFunctions; i++) {
				for (int j = 0; j < exportDirectory->NumberOfNames; j++) {
					if (addressNameOrdinal[j] == i) {
						printf("  %-2x", i + exportDirectory->Base);
						char* name = (char*)(RVAToOffset32(addressName[j], dosHeader) + (DWORD)dosHeader);
						printf("%-36s", name);
						printf("|0x%-8x", addressFunction[i]);
						printf("|0x%-8x\n", addressName[j]);
						break;
					}
				}
			}
		}
	}
}

void printImportSection(IMAGE_DOS_HEADER * dosHeader, BOOL printFunction) {
	IMAGE_IMPORT_DESCRIPTOR* importDirectory;
	IMAGE_DATA_DIRECTORY* dataDirectory;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);

	if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		dataDirectory = ntHeader32->OptionalHeader.DataDirectory;
		importDirectory = (IMAGE_IMPORT_DESCRIPTOR*)(RVAToOffset32(dataDirectory[1].VirtualAddress, dosHeader) + (DWORD)dosHeader);
		while (importDirectory->Name != 0) {
			printf("  %s\n", RVAToOffset32(importDirectory->Name, dosHeader) + (DWORD)dosHeader);
			printf("%-40s|0x%-8x|%d\n", "    OriginalFirstThunk", importDirectory->OriginalFirstThunk, importDirectory->OriginalFirstThunk);
			printf("%-40s|0x%-8x|%d\n", "    TimeDateStamp", importDirectory->TimeDateStamp, importDirectory->TimeDateStamp);
			printf("%-40s|0x%-8x|%d\n", "    ForwarderChain", importDirectory->ForwarderChain, importDirectory->ForwarderChain);
			printf("%-40s|0x%-8x|%d\n", "    Name RVA", importDirectory->Name, importDirectory->Name);
			printf("%-40s|0x%-8x|%d\n", "    FirstThunk", importDirectory->FirstThunk, importDirectory->FirstThunk);

			DWORD thunkRVA = importDirectory->OriginalFirstThunk == 0 ? importDirectory->FirstThunk : importDirectory->OriginalFirstThunk;
			IMAGE_THUNK_DATA32* thunk = (IMAGE_THUNK_DATA32*)(RVAToOffset32(thunkRVA, dosHeader) + (DWORD)dosHeader);

			printf("%-41s%-11s%-10s\n", "   IMPORT FUNCTION", "Ordinal", "FuncAddress");
			while (thunk->u1.AddressOfData != 0) {

				if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					printf("%-40s|0x%-8x|0x%-8x\n", "    Ordinal", thunk->u1.Ordinal, thunk->u1.Function);
				}
				else {
					DWORD nameImportOffset = RVAToOffset32(thunk->u1.AddressOfData, dosHeader);
					IMAGE_IMPORT_BY_NAME* nameImport = (IMAGE_IMPORT_BY_NAME*)(nameImportOffset + (DWORD)dosHeader);
					printf("    %-36s|0x%-8x\n", nameImport->Name, thunk->u1.Ordinal);
				}
				thunk++;
			}
			importDirectory++;
		}
	}
	else if (ntHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		dataDirectory = ntHeader64->OptionalHeader.DataDirectory;
		importDirectory = (IMAGE_IMPORT_DESCRIPTOR*)(RVAToOffset64(dataDirectory[1].VirtualAddress, dosHeader) + (DWORD64)dosHeader);
		while (importDirectory->Name != 0) {
			printf("  %s\n", RVAToOffset64(importDirectory->Name, dosHeader) + (DWORD64)dosHeader);
			printf("%-40s|0x%-8x|%d\n", "    OriginalFirstThunk", importDirectory->OriginalFirstThunk, importDirectory->OriginalFirstThunk);
			printf("%-40s|0x%-8x|%d\n", "    TimeDateStamp", importDirectory->TimeDateStamp, importDirectory->TimeDateStamp);
			printf("%-40s|0x%-8x|%d\n", "    ForwarderChain", importDirectory->ForwarderChain, importDirectory->ForwarderChain);
			printf("%-40s|0x%-8x|%d\n", "    Name RVA", importDirectory->Name, importDirectory->Name);
			printf("%-40s|0x%-8x|%d\n", "    FirstThunk", importDirectory->FirstThunk, importDirectory->FirstThunk);

			DWORD64 thunkRVA = importDirectory->OriginalFirstThunk == 0 ? importDirectory->FirstThunk : importDirectory->OriginalFirstThunk;
			IMAGE_THUNK_DATA64* thunk = (IMAGE_THUNK_DATA64*)(RVAToOffset64(thunkRVA, dosHeader) + (DWORD64)dosHeader);

			printf("%-41s%-11s%-10s\n", "   IMPORT FUNCTION", "Ordinal", "FuncAddress");
			while (thunk->u1.AddressOfData != 0) {

				if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					printf("%-40s|0x%-8x|0x%-8x\n", "    Ordinal", thunk->u1.Ordinal, thunk->u1.Function);
				}
				else {
					DWORD64 nameImportOffset = RVAToOffset64(thunk->u1.AddressOfData, dosHeader);
					IMAGE_IMPORT_BY_NAME* nameImport = (IMAGE_IMPORT_BY_NAME*)(nameImportOffset + (DWORD64)dosHeader);
					printf("    %-36s|0x%-8x\n", nameImport->Name, thunk->u1.Ordinal);
				}
				thunk++;
			}
			importDirectory++;
		}
	}
	else return;

}
