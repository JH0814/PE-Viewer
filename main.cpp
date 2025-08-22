#include<iostream>
#include<string>
#include<windows.h>
#include<fstream>
#include <iomanip>
#include <vector>
#include <cctype>
using namespace std;

void print_dos_header(IMAGE_DOS_HEADER* h){
    cout << hex << uppercase << setfill('0');
    cout << "Signature : " << setw(4) << h->e_magic << endl;
    cout << "Bytes on Last Page of File : " << setw(4) << h->e_cblp << endl;
    cout << "Pages in File : " << setw(4) << h->e_cp << endl;
    cout << "Relocations : " << setw(4) << h->e_crlc << endl;
    cout << "Size of Header in Paragraphs : " << setw(4) << h->e_cparhdr << endl;
    cout << "Minimum Extra Paragraphs : " << setw(4) << h->e_minalloc << endl;
    cout << "Maximum Extra Paragraphs : " << setw(4) << h->e_maxalloc << endl;
    cout << "Initial SS : " << setw(4) << h->e_ss << endl;
    cout << "Initial SP : " << setw(4) << h->e_sp << endl;
    cout << "Checksum : " << setw(4) << h->e_csum << endl;
    cout << "Initial IP : " << setw(4) << h->e_ip << endl;
    cout << "Initial CS : " << setw(4) << h->e_cs << endl;
    cout << "Offset to Relocation Table : " << setw(4) << h->e_lfarlc << endl;
    cout << "Overlay Number : " << setw(4) << h->e_ovno << endl;
    for(int i = 0; i<4; i++){
        cout << "Reserved : " << setw(4) << h->e_res[i] << endl;
    }
    cout << "OEM Identifier : " << setw(4) << h->e_oemid << endl;
    cout << "OEM Information : " << setw(4) << h->e_oeminfo << endl;
    for(int i = 0; i<10; i++){
        cout << "Reserved : " << setw(4) << h->e_res2[i] << endl;
    }
    cout << "Offset to New EXE Header : " << setw(8) << h->e_lfanew << endl;
}

void print_dos_stub(vector<char>& stubData){
    cout << hex << uppercase << setfill('0');
    for (size_t i = 0; i < stubData.size(); ++i) {
        if (i % 16 == 0) {
            if (i > 0) {
                cout << "  ";
                for (size_t j = i - 16; j < i; ++j) {
                    cout << (isprint(static_cast<unsigned char>(stubData[j])) ? stubData[j] : '.');
                }
            }
            cout << "\n" << setw(8) << i + 0x40 << ": ";
        }
        cout << setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(stubData[i])) << " ";
    }
    cout << endl;
}

void print_nt_header(IMAGE_NT_HEADERS32* h){
    cout << hex << uppercase << setfill('0');
    cout << "Signature : " << setw(8) << h->Signature << " ('PE\\0\\0')" << endl;
    cout << "[File Header]" << endl;
    cout << "Machine : " << setw(4) << h->FileHeader.Machine << endl;
    cout << "NumberOfSections : " << setw(4) << h->FileHeader.NumberOfSections << endl;
    cout << "Time Date Stamp : " << setw(8) << h->FileHeader.TimeDateStamp << endl;
    cout << "Pointer to Symbol Table : " << setw(8) << h->FileHeader.PointerToSymbolTable << endl;
    cout << "Size of Optional Header : " << setw(4) << h->FileHeader.SizeOfOptionalHeader << endl;
    cout << "Characteristics : " << setw(4) << h->FileHeader.Characteristics << endl;
    cout << "[Optional Header]" << endl;
    cout << "Magic : " << setw(4) << h->OptionalHeader.Magic << " (PE32)" << endl;
    cout << "Address Of Entry Point : " << setw(8) << h->OptionalHeader.AddressOfEntryPoint << endl;
    cout << "Image Base : " << setw(8) << h->OptionalHeader.ImageBase << endl;
    cout << "Section Alignment : " << setw(8) << h->OptionalHeader.SectionAlignment << endl;
    cout << "File Alignment : " << setw(8) << h->OptionalHeader.FileAlignment << endl;
    cout << "Size of Image : " << setw(8) << h->OptionalHeader.SizeOfImage << endl;
    cout << "Size of Header : " << setw(8) << h->OptionalHeader.SizeOfHeaders << endl;
    cout << "Subsystem : " << setw(4) << h->OptionalHeader.Subsystem << endl;
    cout << "Number Of Data Directories : " << setw(8) << h->OptionalHeader.NumberOfRvaAndSizes << endl;

}

int main(){
    // File Open
    string file_name;
    cout << "Input File Name : ";
    cin >> file_name;
    ifstream fin;
    fin.open(file_name, ios::binary);
    if(!fin){
        cout << "File Open Error" << endl;
        return 1;
    }
    // Read DOS Header
    IMAGE_DOS_HEADER dos_header;
    fin.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));
    if (fin.fail()) {
        cout << "Error : can't read DOS header" << endl;
        fin.close();
        return 1;
    }
    if(dos_header.e_magic != IMAGE_DOS_SIGNATURE){
        cout << "Error : Invalid PE format" << endl;
        fin.close();
        return 1;
    }
    // Read NT Header
    IMAGE_NT_HEADERS32 nt_header;
    fin.seekg(dos_header.e_lfanew, ios::beg);
    fin.read(reinterpret_cast<char*>(&nt_header), sizeof(IMAGE_NT_HEADERS32));
    if(nt_header.Signature != IMAGE_NT_SIGNATURE){
        cout << "Error : Invalid PE format" << endl;
        fin.close();
        return 1; 
    }
    // Run Command
    int command;
    while(1){
        cout << "select menu : ";
        cin >> command;
        switch(command){
            case 1:
                print_dos_header(&dos_header);
                break;
            case 2:{
                long Stub_size = dos_header.e_lfanew - sizeof(IMAGE_DOS_HEADER);
                if(Stub_size <= 0){
                    cout << "Can ignore DOS Stub" << endl;
                }
                else{
                    vector<char> stubBuffer(Stub_size);
                    fin.seekg(sizeof(IMAGE_DOS_HEADER), ios::beg);
                    fin.read(stubBuffer.data(), Stub_size);
                    if (fin.fail()) {
                        cout << "Error : Can't read DOS Stub" << endl;
                    } else {
                        print_dos_stub(stubBuffer);
                    }
                }
                break;
            }
            case 3:
                print_nt_header(&nt_header);
                break;
            case 0:
                fin.close();
                return 0;
            default:
                cout << "Invalid command" << endl;
                break;
        }
    }
}