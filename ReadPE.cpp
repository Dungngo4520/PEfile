#include "Header.h"

VOID printDosHeader(LPVOID fileData) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	DWORD c = 0;
	printf("%-40s|%-8X|%-8s|%X\n", "  e_magic", c, "Word", dosHeader->e_magic);
	c += sizeof(dosHeader->e_magic);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_cblp", c, "Word", dosHeader->e_cblp);
	c += sizeof(dosHeader->e_cblp);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_cp", c, "Word", dosHeader->e_cp);
	c += sizeof(dosHeader->e_cp);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_crlc", c, "Word", dosHeader->e_crlc);
	c += sizeof(dosHeader->e_crlc);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_cparhdr", c, "Word", dosHeader->e_cparhdr);
	c += sizeof(dosHeader->e_cparhdr);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_minalloc", c, "Word", dosHeader->e_minalloc);
	c += sizeof(dosHeader->e_minalloc);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_maxalloc", c, "Word", dosHeader->e_maxalloc);
	c += sizeof(dosHeader->e_maxalloc);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_ss", c, "Word", dosHeader->e_ss);
	c += sizeof(dosHeader->e_ss);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_sp", c, "Word", dosHeader->e_sp);
	c += sizeof(dosHeader->e_sp);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_csum", c, "Word", dosHeader->e_csum);
	c += sizeof(dosHeader->e_csum);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_ip", c, "Word", dosHeader->e_ip);
	c += sizeof(dosHeader->e_ip);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_cs", c, "Word", dosHeader->e_cs);
	c += sizeof(dosHeader->e_cs);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_lfarlc", c, "Word", dosHeader->e_lfarlc);
	c += sizeof(dosHeader->e_lfarlc);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_ovno", c, "Word", dosHeader->e_ovno);
	c += sizeof(dosHeader->e_ovno);
	for (int i = 0; i < 4; i++) {
		printf("%-40s|%-8X|%-8s|%X\n", i == 0 ? "  e_res" : "", c, "Word", dosHeader->e_res[i]);
		c += sizeof(dosHeader->e_res[i]);
	}
	printf("%-40s|%-8X|%-8s|%X\n", "  e_oemid", c, "Word", dosHeader->e_oemid);
	c += sizeof(dosHeader->e_oemid);
	printf("%-40s|%-8X|%-8s|%X\n", "  e_oeminfo", c, "Word", dosHeader->e_oeminfo);
	c += sizeof(dosHeader->e_oeminfo);
	for (int i = 0; i < 10; i++) {
		printf("%-40s|%-8X|%-8s|%X\n", i == 0 ? "  e_res2" : "", c, "Word", dosHeader->e_res2[i]);
		c += sizeof(dosHeader->e_res2[i]);
	}
	printf("%-40s|%-8X|%-8s|%X\n", "  e_lfanew", c, "Dword", dosHeader->e_lfanew);
}

VOID printNtHeader(LPVOID fileData) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	printNtSignature(dosHeader);
	printFileHeader(dosHeader);
	printOptionalHeader(dosHeader);
}

VOID printNtSignature(LPVOID fileData) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	int c = dosHeader->e_lfanew;

	if (is64(dosHeader)) {
		printf("%-40s|%-8X|%-8s|%X\n", "  Signature", c, "Dword", ntHeader64->Signature);
	}
	else {
		printf("%-40s|%-8X|%-8s|%X\n", "  Signature", c, "Dword", ntHeader32->Signature);
	}
}

VOID printFileHeader(LPVOID fileData) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	IMAGE_FILE_HEADER fileHeader;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	int c = dosHeader->e_lfanew + sizeof(IMAGE_NT_SIGNATURE);

	if (is64(dosHeader)) {
		fileHeader = ntHeader64->FileHeader;
	}
	else {
		fileHeader = ntHeader32->FileHeader;
	}

	printf("%-40s\n", "  FileHeader");
	printf("%-40s|%-8X|%-8s|%X\n", "    Characteristics", c, "Word", fileHeader.Machine);
	c += sizeof(fileHeader.Machine);
	printf("%-40s|%-8X|%-8s|%X\n", "    NumberOfSections", c, "Word", fileHeader.NumberOfSections);
	c += sizeof(fileHeader.NumberOfSections);
	printf("%-40s|%-8X|%-8s|%X\n", "    TimeDateStamp", c, "Dword", fileHeader.TimeDateStamp);
	c += sizeof(fileHeader.TimeDateStamp);
	printf("%-40s|%-8X|%-8s|%X\n", "    PointerToSymbolTable", c, "Dword", fileHeader.PointerToSymbolTable);
	c += sizeof(fileHeader.PointerToSymbolTable);
	printf("%-40s|%-8X|%-8s|%X\n", "    NumberOfSymbols", c, "Dword", fileHeader.NumberOfSymbols);
	c += sizeof(fileHeader.NumberOfSymbols);
	printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfOptionalHeader", c, "Word", fileHeader.SizeOfOptionalHeader);
	c += sizeof(fileHeader.SizeOfOptionalHeader);
	printf("%-40s|%-8X|%-8s|%X\n", "    Characteristics", c, "Word", fileHeader.Characteristics);
}

VOID printOptionalHeader(LPVOID fileData) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	int c = dosHeader->e_lfanew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER);

	if (is64(dosHeader)) {
		IMAGE_OPTIONAL_HEADER64 optionalHeader = ntHeader64->OptionalHeader;
		printf("%-40s\n", "  OptionalHeader");
		printf("%-40s|%-8X|%-8s|%X\n", "    Magic", c, "Word", optionalHeader.Magic);
		c += sizeof(optionalHeader.Magic);
		printf("%-40s|%-8X|%-8s|%X\n", "    MajorLinkerVersion", c, "Byte", optionalHeader.MajorLinkerVersion);
		c += sizeof(optionalHeader.MajorLinkerVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    MinorLinkerVersion", c, "Byte", optionalHeader.MinorLinkerVersion);
		c += sizeof(optionalHeader.MinorLinkerVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfCode", c, "Dword", optionalHeader.SizeOfCode);
		c += sizeof(optionalHeader.SizeOfCode);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfInitializedData", c, "Dword", optionalHeader.SizeOfInitializedData);
		c += sizeof(optionalHeader.SizeOfInitializedData);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfUninitializedData", c, "Dword", optionalHeader.SizeOfUninitializedData);
		c += sizeof(optionalHeader.SizeOfUninitializedData);
		printf("%-40s|%-8X|%-8s|%X\n", "    AddressOfEntryPoint", c, "Dword", optionalHeader.AddressOfEntryPoint);
		c += sizeof(optionalHeader.AddressOfEntryPoint);
		printf("%-40s|%-8X|%-8s|%X\n", "    BaseOfCode", c, "Dword", optionalHeader.BaseOfCode);
		c += sizeof(optionalHeader.BaseOfCode);
		printf("%-40s|%-8X|%-8s|%llX\n", "    ImageBase", c, "Dword", optionalHeader.ImageBase);
		c += sizeof(optionalHeader.ImageBase);
		printf("%-40s|%-8X|%-8s|%X\n", "    SectionAlignment", c, "Dword", optionalHeader.SectionAlignment);
		c += sizeof(optionalHeader.SectionAlignment);
		printf("%-40s|%-8X|%-8s|%X\n", "    FileAlignment", c, "Dword", optionalHeader.FileAlignment);
		c += sizeof(optionalHeader.FileAlignment);
		printf("%-40s|%-8X|%-8s|%X\n", "    MajorOperatingSystemVersion", c, "Word", optionalHeader.MajorOperatingSystemVersion);
		c += sizeof(optionalHeader.MajorOperatingSystemVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    MinorOperatingSystemVersion", c, "Word", optionalHeader.MinorOperatingSystemVersion);
		c += sizeof(optionalHeader.MinorOperatingSystemVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    MajorImageVersion", c, "Word", optionalHeader.MajorImageVersion);
		c += sizeof(optionalHeader.MajorImageVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    MinorImageVersion", c, "Word", optionalHeader.MinorImageVersion);
		c += sizeof(optionalHeader.MinorImageVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    MajorSubsystemVersion", c, "Word", optionalHeader.MajorSubsystemVersion);
		c += sizeof(optionalHeader.MajorSubsystemVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    MinorSubsystemVersion", c, "Word", optionalHeader.MinorSubsystemVersion);
		c += sizeof(optionalHeader.MinorSubsystemVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    Win32VersionValue", c, "Dword", optionalHeader.Win32VersionValue);
		c += sizeof(optionalHeader.Win32VersionValue);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfImage", c, "Dword", optionalHeader.SizeOfImage);
		c += sizeof(optionalHeader.SizeOfImage);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfHeaders", c, "Dword", optionalHeader.SizeOfHeaders);
		c += sizeof(optionalHeader.SizeOfHeaders);
		printf("%-40s|%-8X|%-8s|%X\n", "    CheckSum", c, "Dword", optionalHeader.CheckSum);
		c += sizeof(optionalHeader.CheckSum);
		printf("%-40s|%-8X|%-8s|%X\n", "    Subsystem", c, "Word", optionalHeader.Subsystem);
		c += sizeof(optionalHeader.Subsystem);
		printf("%-40s|%-8X|%-8s|%X\n", "    DllCharacteristics", c, "Word", optionalHeader.DllCharacteristics);
		c += sizeof(optionalHeader.DllCharacteristics);
		printf("%-40s|%-8X|%-8s|%llX\n", "    SizeOfStackReserve", c, "Dword", optionalHeader.SizeOfStackReserve);
		c += sizeof(optionalHeader.SizeOfStackReserve);
		printf("%-40s|%-8X|%-8s|%llX\n", "    SizeOfStackCommit", c, "Dword", optionalHeader.SizeOfStackCommit);
		c += sizeof(optionalHeader.SizeOfStackCommit);
		printf("%-40s|%-8X|%-8s|%llX\n", "    SizeOfHeapReserve", c, "Dword", optionalHeader.SizeOfHeapReserve);
		c += sizeof(optionalHeader.SizeOfHeapReserve);
		printf("%-40s|%-8X|%-8s|%llX\n", "    SizeOfHeapCommit", c, "Dword", optionalHeader.SizeOfHeapCommit);
		c += sizeof(optionalHeader.SizeOfHeapCommit);
		printf("%-40s|%-8X|%-8s|%X\n", "    LoaderFlags", c, "Dword", optionalHeader.LoaderFlags);
		c += sizeof(optionalHeader.LoaderFlags);
		printf("%-40s|%-8X|%-8s|%X\n", "    NumberOfRvaAndSizes", c, "Dword", optionalHeader.NumberOfRvaAndSizes);
	}
	else {
		IMAGE_OPTIONAL_HEADER32 optionalHeader = ntHeader32->OptionalHeader;
		printf("%-40s\n", "  OptionalHeader");
		printf("%-40s|%-8X|%-8s|%X\n", "    Magic", c, "Word", optionalHeader.Magic);
		c += sizeof(optionalHeader.Magic);
		printf("%-40s|%-8X|%-8s|%X\n", "    MajorLinkerVersion", c, "Byte", optionalHeader.MajorLinkerVersion);
		c += sizeof(optionalHeader.MajorLinkerVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    MinorLinkerVersion", c, "Byte", optionalHeader.MinorLinkerVersion);
		c += sizeof(optionalHeader.MinorLinkerVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfCode", c, "Dword", optionalHeader.SizeOfCode);
		c += sizeof(optionalHeader.SizeOfCode);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfInitializedData", c, "Dword", optionalHeader.SizeOfInitializedData);
		c += sizeof(optionalHeader.SizeOfInitializedData);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfUninitializedData", c, "Dword", optionalHeader.SizeOfUninitializedData);
		c += sizeof(optionalHeader.SizeOfUninitializedData);
		printf("%-40s|%-8X|%-8s|%X\n", "    AddressOfEntryPoint", c, "Dword", optionalHeader.AddressOfEntryPoint);
		c += sizeof(optionalHeader.AddressOfEntryPoint);
		printf("%-40s|%-8X|%-8s|%X\n", "    BaseOfCode", c, "Dword", optionalHeader.BaseOfCode);
		c += sizeof(optionalHeader.BaseOfCode);
		printf("%-40s|%-8X|%-8s|%X\n", "    BaseOfData", c, "Dword", optionalHeader.BaseOfData);
		c += sizeof(optionalHeader.BaseOfData);
		printf("%-40s|%-8X|%-8s|%X\n", "    ImageBase", c, "Dword", optionalHeader.ImageBase);
		c += sizeof(optionalHeader.ImageBase);
		printf("%-40s|%-8X|%-8s|%X\n", "    SectionAlignment", c, "Dword", optionalHeader.SectionAlignment);
		c += sizeof(optionalHeader.SectionAlignment);
		printf("%-40s|%-8X|%-8s|%X\n", "    FileAlignment", c, "Dword", optionalHeader.FileAlignment);
		c += sizeof(optionalHeader.FileAlignment);
		printf("%-40s|%-8X|%-8s|%X\n", "    MajorOperatingSystemVersion", c, "Word", optionalHeader.MajorOperatingSystemVersion);
		c += sizeof(optionalHeader.MajorOperatingSystemVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    MinorOperatingSystemVersion", c, "Word", optionalHeader.MinorOperatingSystemVersion);
		c += sizeof(optionalHeader.MinorOperatingSystemVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    MajorImageVersion", c, "Word", optionalHeader.MajorImageVersion);
		c += sizeof(optionalHeader.MajorImageVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    MinorImageVersion", c, "Word", optionalHeader.MinorImageVersion);
		c += sizeof(optionalHeader.MinorImageVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    MajorSubsystemVersion", c, "Word", optionalHeader.MajorSubsystemVersion);
		c += sizeof(optionalHeader.MajorSubsystemVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    MinorSubsystemVersion", c, "Word", optionalHeader.MinorSubsystemVersion);
		c += sizeof(optionalHeader.MinorSubsystemVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "    Win32VersionValue", c, "Dword", optionalHeader.Win32VersionValue);
		c += sizeof(optionalHeader.Win32VersionValue);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfImage", c, "Dword", optionalHeader.SizeOfImage);
		c += sizeof(optionalHeader.SizeOfImage);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfHeaders", c, "Dword", optionalHeader.SizeOfHeaders);
		c += sizeof(optionalHeader.SizeOfHeaders);
		printf("%-40s|%-8X|%-8s|%X\n", "    CheckSum", c, "Dword", optionalHeader.CheckSum);
		c += sizeof(optionalHeader.CheckSum);
		printf("%-40s|%-8X|%-8s|%X\n", "    Subsystem", c, "Word", optionalHeader.Subsystem);
		c += sizeof(optionalHeader.Subsystem);
		printf("%-40s|%-8X|%-8s|%X\n", "    DllCharacteristics", c, "Word", optionalHeader.DllCharacteristics);
		c += sizeof(optionalHeader.DllCharacteristics);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfStackReserve", c, "Dword", optionalHeader.SizeOfStackReserve);
		c += sizeof(optionalHeader.SizeOfStackReserve);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfStackCommit", c, "Dword", optionalHeader.SizeOfStackCommit);
		c += sizeof(optionalHeader.SizeOfStackCommit);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfHeapReserve", c, "Dword", optionalHeader.SizeOfHeapReserve);
		c += sizeof(optionalHeader.SizeOfHeapReserve);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfHeapCommit", c, "Dword", optionalHeader.SizeOfHeapCommit);
		c += sizeof(optionalHeader.SizeOfHeapCommit);
		printf("%-40s|%-8X|%-8s|%X\n", "    LoaderFlags", c, "Dword", optionalHeader.LoaderFlags);
		c += sizeof(optionalHeader.LoaderFlags);
		printf("%-40s|%-8X|%-8s|%X\n", "    NumberOfRvaAndSizes", c, "Dword", optionalHeader.NumberOfRvaAndSizes);
	}
}

VOID printDataDirectory(LPVOID fileData) {
	IMAGE_DATA_DIRECTORY* dataDirectory;
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	int c = dosHeader->e_lfanew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER);
	if (is64(dosHeader)) {
		dataDirectory = ntHeader64->OptionalHeader.DataDirectory;
		c += ntHeader64->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_DATA_DIRECTORY) * 16;
	}
	else {
		dataDirectory = ntHeader32->OptionalHeader.DataDirectory;
		c += ntHeader32->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_DATA_DIRECTORY) * 16;
	}

	printf("%-40s|%-8X|%-8s|%X\n", "  Export Directory RVA", c, "Dword", dataDirectory[0].VirtualAddress);
	c += sizeof(dataDirectory[0].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  Export Directory Size", c, "Dword", dataDirectory[0].Size);
	c += sizeof(dataDirectory[0].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  Import Directory RVA", c, "Dword", dataDirectory[1].VirtualAddress);
	c += sizeof(dataDirectory[1].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  Import Directory Size", c, "Dword", dataDirectory[1].Size);
	c += sizeof(dataDirectory[1].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  Resource Directory RVA", c, "Dword", dataDirectory[2].VirtualAddress);
	c += sizeof(dataDirectory[2].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  Resource Directory Size", c, "Dword", dataDirectory[2].Size);
	c += sizeof(dataDirectory[2].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  Exception Directory RVA", c, "Dword", dataDirectory[3].VirtualAddress);
	c += sizeof(dataDirectory[3].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  Exception Directory Size", c, "Dword", dataDirectory[3].Size);
	c += sizeof(dataDirectory[3].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  Security Directory RVA", c, "Dword", dataDirectory[4].VirtualAddress);
	c += sizeof(dataDirectory[4].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  Security Directory Size", c, "Dword", dataDirectory[4].Size);
	c += sizeof(dataDirectory[4].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  Relocation Directory RVA", c, "Dword", dataDirectory[5].VirtualAddress);
	c += sizeof(dataDirectory[5].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  Relocation Directory Size", c, "Dword", dataDirectory[5].Size);
	c += sizeof(dataDirectory[5].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  Debug Directory RVA", c, "Dword", dataDirectory[6].VirtualAddress);
	c += sizeof(dataDirectory[6].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  Debug Directory Size", c, "Dword", dataDirectory[6].Size);
	c += sizeof(dataDirectory[6].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  Architecture Directory RVA", c, "Dword", dataDirectory[7].VirtualAddress);
	c += sizeof(dataDirectory[7].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  Architecture Directory Size", c, "Dword", dataDirectory[7].Size);
	c += sizeof(dataDirectory[7].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  Global Pointer Directory RVA", c, "Dword", dataDirectory[8].VirtualAddress);
	c += sizeof(dataDirectory[8].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  Global Pointer Directory Size", c, "Dword", dataDirectory[8].Size);
	c += sizeof(dataDirectory[8].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  TLS Directory RVA", c, "Dword", dataDirectory[9].VirtualAddress);
	c += sizeof(dataDirectory[9].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  TLS Directory Size", c, "Dword", dataDirectory[9].Size);
	c += sizeof(dataDirectory[9].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  Configuration Directory RVA", c, "Dword", dataDirectory[10].VirtualAddress);
	c += sizeof(dataDirectory[10].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  Configuration Directory Size", c, "Dword", dataDirectory[10].Size);
	c += sizeof(dataDirectory[10].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  Bound Import Directory RVA", c, "Dword", dataDirectory[11].VirtualAddress);
	c += sizeof(dataDirectory[11].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  Bound Import Directory Size", c, "Dword", dataDirectory[11].Size);
	c += sizeof(dataDirectory[11].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  Import Address Table Directory RVA", c, "Dword", dataDirectory[12].VirtualAddress);
	c += sizeof(dataDirectory[12].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  Import Address Table Directory Size", c, "Dword", dataDirectory[12].Size);
	c += sizeof(dataDirectory[12].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  Delay Import Directory RVA", c, "Dword", dataDirectory[13].VirtualAddress);
	c += sizeof(dataDirectory[13].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  Delay Import Directory Size", c, "Dword", dataDirectory[13].Size);
	c += sizeof(dataDirectory[13].Size);
	printf("%-40s|%-8X|%-8s|%X\n", "  .NET MetaData Directory RVA", c, "Dword", dataDirectory[14].VirtualAddress);
	c += sizeof(dataDirectory[14].VirtualAddress);
	printf("%-40s|%-8X|%-8s|%X\n", "  .NET MetaData Directory Size", c, "Dword", dataDirectory[14].Size);
	c += sizeof(dataDirectory[14].Size);
}

VOID printSectionHeaders(LPVOID fileData) {
	IMAGE_FILE_HEADER fileHeader;
	IMAGE_SECTION_HEADER* sectionHeader;
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	int c = dosHeader->e_lfanew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER);
	if (is64(dosHeader)) {
		fileHeader = ntHeader64->FileHeader;
		sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD64)ntHeader64 + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader);
		c += fileHeader.SizeOfOptionalHeader;
	}
	else {
		fileHeader = ntHeader32->FileHeader;
		sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD64)ntHeader32 + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader);
		c += fileHeader.SizeOfOptionalHeader;
	}

	for (int i = 0; i < fileHeader.NumberOfSections; i++) {
		printf("  %-38s|%-8X\n", sectionHeader[i].Name, c);
		c += sizeof(sectionHeader[i].Name);
		printf("%-40s|%-8X|%-8s|%X\n", "    VirtualSize", c, "Dword", sectionHeader[i].Misc.VirtualSize);
		c += sizeof(sectionHeader[i].Misc.VirtualSize);
		printf("%-40s|%-8X|%-8s|%X\n", "    VirtualAddress", c, "Dword", sectionHeader[i].VirtualAddress);
		c += sizeof(sectionHeader[i].VirtualAddress);
		printf("%-40s|%-8X|%-8s|%X\n", "    SizeOfRawData", c, "Dword", sectionHeader[i].SizeOfRawData);
		c += sizeof(sectionHeader[i].SizeOfRawData);
		printf("%-40s|%-8X|%-8s|%X\n", "    PointerToRawData", c, "Dword", sectionHeader[i].PointerToRawData);
		c += sizeof(sectionHeader[i].PointerToRawData);
		printf("%-40s|%-8X|%-8s|%X\n", "    PointerToRelocations", c, "Dword", sectionHeader[i].PointerToRelocations);
		c += sizeof(sectionHeader[i].PointerToRelocations);
		printf("%-40s|%-8X|%-8s|%X\n", "    PointerToLinenumbers", c, "Dword", sectionHeader[i].PointerToLinenumbers);
		c += sizeof(sectionHeader[i].PointerToLinenumbers);
		printf("%-40s|%-8X|%-8s|%X\n", "    NumberOfRelocations", c, "Word", sectionHeader[i].NumberOfRelocations);
		c += sizeof(sectionHeader[i].NumberOfRelocations);
		printf("%-40s|%-8X|%-8s|%X\n", "    NumberOfLinenumbers", c, "Word", sectionHeader[i].NumberOfLinenumbers);
		c += sizeof(sectionHeader[i].NumberOfLinenumbers);
		printf("%-40s|%-8X|%-8s|%X\n", "    Characteristics", c, "Dword", sectionHeader[i].Characteristics);
		c += sizeof(sectionHeader[i].Characteristics);
	}
}

VOID printExportSection(LPVOID fileData, BOOL printFunction) {
	IMAGE_DATA_DIRECTORY* dataDirectory;
	IMAGE_EXPORT_DIRECTORY* exportDirectory;
	IMAGE_SECTION_HEADER sectionHeader;
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	if (is64(dosHeader)) {
		dataDirectory = ntHeader64->OptionalHeader.DataDirectory;
		exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(RVAToOffset(dataDirectory[0].VirtualAddress, dosHeader) + (DWORD64)dosHeader);
	}
	else {
		dataDirectory = ntHeader32->OptionalHeader.DataDirectory;
		exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(RVAToOffset(dataDirectory[0].VirtualAddress, dosHeader) + (DWORD64)dosHeader);
	}
	int c = (DWORD64)exportDirectory - (DWORD64)dosHeader;

	if (dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0) {

		printf("%-40s|%-8X|%-8s|%X\n", "  Characteristics", c, "Dword", exportDirectory->Characteristics);
		c += sizeof(exportDirectory->Characteristics);
		printf("%-40s|%-8X|%-8s|%X\n", "  TimeDateStamp", c, "Dword", exportDirectory->TimeDateStamp);
		c += sizeof(exportDirectory->TimeDateStamp);
		printf("%-40s|%-8X|%-8s|%X\n", "  MajorVersion", c, "Word", exportDirectory->MajorVersion);
		c += sizeof(exportDirectory->MajorVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "  MinorVersion", c, "Word", exportDirectory->MinorVersion);
		c += sizeof(exportDirectory->MinorVersion);
		printf("%-40s|%-8X|%-8s|%X\n", "  Name", c, "Dword", exportDirectory->Name);
		c += sizeof(exportDirectory->Name);
		printf("%-40s|%-8X|%-8s|%X\n", "  Base", c, "Dword", exportDirectory->Base);
		c += sizeof(exportDirectory->Base);
		printf("%-40s|%-8X|%-8s|%X\n", "  NumberOfFunctions", c, "Dword", exportDirectory->NumberOfFunctions);
		c += sizeof(exportDirectory->NumberOfFunctions);
		printf("%-40s|%-8X|%-8s|%X\n", "  NumberOfNames", c, "Dword", exportDirectory->NumberOfNames);
		c += sizeof(exportDirectory->NumberOfNames);
		printf("%-40s|%-8X|%-8s|%X\n", "  AddressOfFunctions", c, "Dword", exportDirectory->AddressOfFunctions);
		c += sizeof(exportDirectory->AddressOfFunctions);
		printf("%-40s|%-8X|%-8s|%X\n", "  AddressOfNames", c, "Dword", exportDirectory->AddressOfNames);
		c += sizeof(exportDirectory->AddressOfNames);
		printf("%-40s|%-8X|%-8s|%X\n", "  AddressOfNameOrdinals", c, "Dword", exportDirectory->AddressOfNameOrdinals);
		c += sizeof(exportDirectory->AddressOfNameOrdinals);

		if (printFunction) {
			DWORD* addressFunction = (DWORD*)(RVAToOffset(exportDirectory->AddressOfFunctions, dosHeader) + (DWORD64)dosHeader);
			DWORD* addressName = (DWORD*)(RVAToOffset(exportDirectory->AddressOfNames, dosHeader) + (DWORD64)dosHeader);
			WORD* addressNameOrdinal = (WORD*)(RVAToOffset(exportDirectory->AddressOfNameOrdinals, dosHeader) + (DWORD64)dosHeader);

			printf("\n%-41s%-11s%-10s\n", "  EXPORT FUNCTION", "FuncRVA", "NameRVA");
			for (int i = 0; i < exportDirectory->NumberOfFunctions; i++) {
				if (addressFunction[i] == 0)continue;
				BOOL named = FALSE;
				for (int j = 0; j < exportDirectory->NumberOfNames; j++) {
					if (addressNameOrdinal[j] == i) {
						named = TRUE;
						char* name = (char*)(RVAToOffset(addressName[j], dosHeader) + (DWORD64)dosHeader);
						printf("  %-5x%-33s|%-8X|%-8X\n", i + exportDirectory->Base, name, addressFunction[i], addressName[j]);
						break;
					}
				}
				if (!named) {
					printf("  %-5x%-33s|%-8X\n", i + exportDirectory->Base, "", addressFunction[i]);
				}
			}
		}
	}
}

VOID printImportSection(LPVOID fileData, BOOL printFunction) {
	IMAGE_IMPORT_DESCRIPTOR* importDirectory;
	IMAGE_DATA_DIRECTORY* dataDirectory;
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	IMAGE_NT_HEADERS32* ntHeader32 = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	int c = 0;
	if (is64(dosHeader)) {
		dataDirectory = ntHeader64->OptionalHeader.DataDirectory;
		importDirectory = (IMAGE_IMPORT_DESCRIPTOR*)(RVAToOffset(dataDirectory[1].VirtualAddress, dosHeader) + (DWORD64)dosHeader);
		c = (DWORD64)importDirectory - (DWORD64)dosHeader;
		while (importDirectory->Name != 0) {
			printf("%-40s|%-8llX\n", (char*)RVAToOffset(importDirectory->Name, dosHeader) + (DWORD64)dosHeader, RVAToOffset(importDirectory->Name, dosHeader));
			printf("%-40s|%-8X|%-8s|%X\n", "  OriginalFirstThunk", c, "Dword", importDirectory->OriginalFirstThunk);
			c += sizeof(importDirectory->OriginalFirstThunk);
			printf("%-40s|%-8X|%-8s|%X\n", "  TimeDateStamp", c, "Dword", importDirectory->TimeDateStamp);
			c += sizeof(importDirectory->TimeDateStamp);
			printf("%-40s|%-8X|%-8s|%X\n", "  ForwarderChain", c, "Dword", importDirectory->ForwarderChain);
			c += sizeof(importDirectory->ForwarderChain);
			printf("%-40s|%-8X|%-8s|%X\n", "  Name RVA", c, "Dword", importDirectory->Name);
			c += sizeof(importDirectory->Name);
			printf("%-40s|%-8X|%-8s|%X\n", "  FirstThunk (IAT)", c, "Dword", importDirectory->FirstThunk);
			c += sizeof(importDirectory->FirstThunk);

			DWORD64 thunkRVA = importDirectory->OriginalFirstThunk == 0 ? importDirectory->FirstThunk : importDirectory->OriginalFirstThunk;
			IMAGE_THUNK_DATA64* thunk = (IMAGE_THUNK_DATA64*)(RVAToOffset(thunkRVA, dosHeader) + (DWORD64)dosHeader);
			if (printFunction) {
				printf("%-41s%-9s%-9s%-10s\n", "   IMPORT FUNCTION", "Offset", "Hint", "OFTs");
				while (thunk->u1.AddressOfData != 0) {

					if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
						printf("    %-36s|%-8llX|%-8llX\n", "", thunk->u1.Ordinal, thunk->u1.Function);
					}
					else {
						DWORD nameImportOffset = RVAToOffset(thunk->u1.AddressOfData, dosHeader);
						IMAGE_IMPORT_BY_NAME* nameImport = (IMAGE_IMPORT_BY_NAME*)(nameImportOffset + (DWORD64)dosHeader);
						printf("    %-36s|%-8X|%-8X|%-8llX\n", nameImport->Name, nameImportOffset, nameImport->Hint, thunk->u1.Ordinal);
					}
					thunk++;
				}
			}
			importDirectory++;
		}
	}
	else {
		dataDirectory = ntHeader32->OptionalHeader.DataDirectory;
		importDirectory = (IMAGE_IMPORT_DESCRIPTOR*)(RVAToOffset(dataDirectory[1].VirtualAddress, dosHeader) + (DWORD64)dosHeader);
		c = (DWORD64)importDirectory - (DWORD64)dosHeader;
		while (importDirectory->Name != 0) {
			printf("%-40s|%-8llX\n", (char*)RVAToOffset(importDirectory->Name, dosHeader) + (DWORD64)dosHeader, RVAToOffset(importDirectory->Name, dosHeader));
			printf("%-40s|%-8X|%-8s|%X\n", "  OriginalFirstThunk", c, "Dword", importDirectory->OriginalFirstThunk);
			c += sizeof(importDirectory->OriginalFirstThunk);
			printf("%-40s|%-8X|%-8s|%X\n", "  TimeDateStamp", c, "Dword", importDirectory->TimeDateStamp);
			c += sizeof(importDirectory->TimeDateStamp);
			printf("%-40s|%-8X|%-8s|%X\n", "  ForwarderChain", c, "Dword", importDirectory->ForwarderChain);
			c += sizeof(importDirectory->ForwarderChain);
			printf("%-40s|%-8X|%-8s|%X\n", "  Name RVA", c, "Dword", importDirectory->Name);
			c += sizeof(importDirectory->Name);
			printf("%-40s|%-8X|%-8s|%X\n", "  FirstThunk (IAT)", c, "Dword", importDirectory->FirstThunk);
			c += sizeof(importDirectory->FirstThunk);

			DWORD thunkRVA = importDirectory->OriginalFirstThunk == 0 ? importDirectory->FirstThunk : importDirectory->OriginalFirstThunk;
			IMAGE_THUNK_DATA32* thunk = (IMAGE_THUNK_DATA32*)(RVAToOffset(thunkRVA, dosHeader) + (DWORD64)dosHeader);
			if (printFunction) {
				printf("%-41s%-9s%-9s%-10s\n", "   IMPORT FUNCTION", "Offset", "Hint", "OFTs");
				while (thunk->u1.AddressOfData != 0) {

					if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
						printf("    %-36s|%-8X|%-8X\n", "", thunk->u1.Ordinal, thunk->u1.Function);
					}
					else {
						DWORD nameImportOffset = RVAToOffset(thunk->u1.AddressOfData, dosHeader);
						IMAGE_IMPORT_BY_NAME* nameImport = (IMAGE_IMPORT_BY_NAME*)(nameImportOffset + (DWORD64)dosHeader);
						printf("    %-36s|%-8X|%-8X|%-8X\n", nameImport->Name, nameImportOffset, nameImport->Hint, thunk->u1.Ordinal);
					}
					thunk++;
				}
			}
			importDirectory++;
		}
	}
}

BOOL PEValidate(LPVOID fileData) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	IMAGE_NT_HEADERS64* ntHeader = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}
	return TRUE;
}

VOID getFileData(char * fileName, LPVOID * fileData, LPDWORD fileSize) {
	HANDLE hFile;
	DWORD byteRead = 0;
	if (strnlen_s(fileName, MAX_PATH + 1) > MAX_PATH) {
		Error("Path too long", FALSE, TRUE, 1);
	}
	hFile = CreateFile(fileName, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		Error("Cannot open file.", TRUE, TRUE, 1);
	}

	*fileSize = GetFileSize(hFile, NULL);

	*fileData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *fileSize);
	if (!*fileData) {
		Error("Cannot allocate memory.", FALSE, TRUE, 1);
	}
	if (!ReadFile(hFile, *fileData, *fileSize, &byteRead, NULL)) {
		Error("Cannot read file.", TRUE, TRUE, 1);
	}
	CloseHandle(hFile);
}

VOID Error(char* ErrorMessage, BOOL printErrorCode, BOOL isReturn, int exitCode) {
	printf(ErrorMessage);
	if (printErrorCode)
		printf("\nError: %d\n", GetLastError());
	getchar();
	if (isReturn)
		ExitProcess(exitCode);
}

DWORD64 RVAToOffset(DWORD64 RVA, LPVOID fileData) {
	IMAGE_SECTION_HEADER* sectionHeader;
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);

	sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD64)ntHeader64 + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + ntHeader64->FileHeader.SizeOfOptionalHeader);
	if (RVA == 0)return 0;
	for (int i = 0; i < ntHeader64->FileHeader.NumberOfSections; i++) {
		if (RVA >= sectionHeader[i].VirtualAddress && RVA - sectionHeader[i].VirtualAddress < +sectionHeader[i].Misc.VirtualSize) {
			return RVA - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData;
		}
	}
	return 0;
}

DWORD64 OffsetToRVA(DWORD64 Offset, LPVOID fileData) {
	IMAGE_SECTION_HEADER* sectionHeader;
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);

	sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD64)ntHeader64 + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + ntHeader64->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < ntHeader64->FileHeader.NumberOfSections; i++) {
		if (Offset >= sectionHeader[i].PointerToRawData && Offset - sectionHeader[i].PointerToRawData < sectionHeader[i].SizeOfRawData) {
			return Offset - sectionHeader[i].PointerToRawData + sectionHeader[i].VirtualAddress;
		}
	}
	return 0;
}

BOOL is64(LPVOID fileData) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	if (ntHeader64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return TRUE;
	}
	else return FALSE;
}

BOOL isExecutable(LPVOID fileData) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	IMAGE_NT_HEADERS64* ntHeader64 = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	if (ntHeader64->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
		return TRUE;
	}
	return FALSE;
}