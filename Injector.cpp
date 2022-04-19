#include<Windows.h>
#include"Header.h"

PE parsePEFile(IMAGE_DOS_HEADER* dosHeader) {
	PE pe;
	memcpy_s(&pe.dosHeader, sizeof(IMAGE_DOS_HEADER), dosHeader, sizeof(IMAGE_DOS_HEADER));
	DWORD stubSize = dosHeader->e_lfanew - 0x3c - sizeof(dosHeader->e_lfanew);
	memcpy_s(&pe.DOS_STUB, stubSize, dosHeader + 0x3c + sizeof(dosHeader->e_lfanew), stubSize);
	if (!is64(dosHeader)) {
		IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((DWORD64)dosHeader + dosHeader->e_lfanew);
		memcpy_s(&pe.ntHeader32, sizeof(IMAGE_NT_HEADERS32), ntHeader, sizeof(IMAGE_NT_HEADERS32));
		IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD64)ntHeader + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader);

		for (int i = 0; i < ntHeader->FileHeader.NumberOfSections;i++) {
			memcpy_s(&pe.sectionHeader[i], sizeof(IMAGE_SECTION_HEADER), &sectionHeader[i], sizeof(IMAGE_SECTION_HEADER));
			memcpy_s(pe.sections[i], sectionHeader[i].SizeOfRawData, dosHeader + sectionHeader[i].PointerToRawData, sectionHeader[i].SizeOfRawData);

		}
	}
	else {
		memcpy_s(&pe.ntHeader64, sizeof(IMAGE_NT_HEADERS64), dosHeader + dosHeader->e_lfanew, sizeof(IMAGE_NT_HEADERS64));
	}

	return pe;
}