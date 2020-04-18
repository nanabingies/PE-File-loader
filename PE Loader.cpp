#include <iostream>
#include <stdio.h>
#include <string>
#include <windows.h>
#include <ddk/ntddk.h>
using namespace std;

void myError(string, DWORD);

int main(int argc, char* argv[]){
    //TCHAR AppName[] = TEXT("C:\\Users\\prof\\Desktop\\Unknown.exe");
    TCHAR AppName[100];
    HANDLE hFile, pFileMapping;
    LPVOID pMapOfView;
    PIMAGE_DOS_HEADER pdosHdr;
    PIMAGE_NT_HEADERS pntHdr;
    PIMAGE_SECTION_HEADER pscHdr;
    DWORD nSize, i;

    /*if (argc != 2){
        cout << "Usage : " << argv[0] << " <filename>" << endl;
        exit (-1);
    }*/

    cout << "Enter File Name : ";
    fgets(AppName, sizeof(AppName), stdin);
    if ((AppName[strlen(AppName)-1]) == '\n')
        AppName[strlen(AppName)-1] = '\0';

    hFile = CreateFile(AppName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        myError("CreateFile Error", GetLastError());

    pFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (pFileMapping == NULL)
        myError("CreateFileMapping Error", GetLastError());

    pMapOfView = MapViewOfFile(pFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (pMapOfView == NULL)
        myError("MapViewOfFile Error", GetLastError());

    pdosHdr = (PIMAGE_DOS_HEADER)pMapOfView;
    if (pdosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        myError("Executable is not a valid PE File.", GetLastError());
    pntHdr = (PIMAGE_NT_HEADERS)((DWORD)pdosHdr + (DWORD)pdosHdr->e_lfanew);
    if (pntHdr->Signature != IMAGE_NT_SIGNATURE)
        myError("Executable is not a valid PE File.", GetLastError());
    cout << "\n\n****************************************************************\n\n";
    cout << "PE LOADER Coded by Nana Bingies.\n";
    cout << "\nFILE LOADED : " << AppName <<endl;
    cout << "\n##################################################################\n\n";
    cout << "Dumping DOS Header INFO\n";
    cout << "Magic Number : " << hex << pdosHdr->e_magic << endl;
    cout << "Bytes on last page on file : " << hex << pdosHdr->e_cblp << endl;
    cout << "Pages in file : " << hex << pdosHdr->e_cp << endl;
    cout << "Relocation : " << hex << pdosHdr->e_crlc << endl;
    cout << "File Address of Relocation table : " << hex << pdosHdr->e_lfarlc << endl;
    cout << "RVA Address Of PE Header : " << hex << pdosHdr->e_lfanew << endl;
    cout << "End Of DOS Header Dump\n";
    cout << "\n##################################################################\n\n";
    cout << "\n##################################################################\n\n";
    cout << "Dumping PE Header INFO\n";
    cout << "Time Stamp : " << pntHdr->FileHeader.TimeDateStamp << endl;
    cout << "Size Of Optional Headers : " << hex << pntHdr->FileHeader.SizeOfOptionalHeader << endl;
    cout << "Number Of Sections in : " << dec << pntHdr->FileHeader.NumberOfSections << endl;
    cout << "Number Of Entries in Symbol Table : " << dec << pntHdr->FileHeader.NumberOfSymbols << endl;
    cout << "Address Of Entry Point : " << hex << pntHdr->OptionalHeader.AddressOfEntryPoint << endl;
    cout << "Base Address : " << hex << pntHdr->OptionalHeader.ImageBase << endl;
    cout << "Base Of Address Code : " << hex << pntHdr->OptionalHeader.BaseOfCode << endl;
    cout << "Base Of Address Data : " << hex << pntHdr->OptionalHeader.BaseOfData << endl;
    cout << "Size Of code segment : " << hex << pntHdr->OptionalHeader.SizeOfCode << endl;
    cout << "Section Alignment : " << hex << pntHdr->OptionalHeader.SectionAlignment << endl;
    cout << "Major Linker Version : " << dec << pntHdr->OptionalHeader.MajorImageVersion << endl;
    cout << "Minor Linker Version : " << dec << pntHdr->OptionalHeader.MinorLinkerVersion << endl;
    cout << "End Of PE Header INFO\n";
    cout << "\n####################################################################\n\n";
    nSize = pntHdr->FileHeader.NumberOfSections;
    cout << "\n####################################################################\n\n";
    cout << "\nDumping Section Header INFO\n";
    for (pscHdr=IMAGE_FIRST_SECTION(pntHdr),i=0; i<nSize; i++, pscHdr++){
        cout << "\n----------------------------\n";
        cout << "Section Number : " << i+1 << endl;
        cout << "Name : " << pscHdr->Name << endl;
        cout << "Virtual Address (VA) : " << hex << pscHdr->VirtualAddress << endl;
        cout << "Size Of RAW Data : " << hex << pscHdr->SizeOfRawData << endl;
        cout << "Pointer to Relocations : " << hex<< pscHdr->PointerToRelocations << endl;
    }

    return EXIT_SUCCESS;
}

void myError(string message, DWORD ErrorCode){
    cout << message << endl;
    cout << "Exiting with Error Code " << ErrorCode << endl;
    exit(-1);
}
