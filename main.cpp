#include<iostream>
#include<string>
#include<windows.h>
#include<fstream>
#include <iomanip>
#include <vector>
#include <cctype>
using namespace std;

void logo_start(){
    cout << "+------------------------------------------------------+" << endl;
    cout << "|                                                      |" << endl;
    cout << "|                                                      |" << endl;
    cout << "|                                                      |" << endl;
    cout << "|                      PE Viewer                       |" << endl;
    cout << "|                                                      |" << endl;
    cout << "|                                                      |" << endl;
    cout << "|                                                      |" << endl;
    cout << "+------------------------------------------------------+" << endl;
}

void print_menu(){
    cout << "+------------------------------------+" << endl;
    cout << "|            PE Viewer Menu          |" << endl;
    cout << "+------------------------------------+" << endl;
    cout << "| 1. DOS Header                      |" << endl;
    cout << "| 2. DOS Stub                        |" << endl;
    cout << "| 3. NT Headers                      |" << endl;
    cout << "| 4. Section Headers                 |" << endl;
    cout << "+------------------------------------+" << endl;
    cout << "| 5. IDT                             |" << endl;
    cout << "| 6. INT                             |" << endl;
    cout << "| 7. IAT                             |" << endl;
    cout << "| 8. EAT Header                      |" << endl;
    cout << "+------------------------------------+" << endl;
    cout << "| 0. Exit                            |" << endl;
    cout << "+------------------------------------+" << endl;
}

DWORD RVAToRAW(DWORD rva, vector<IMAGE_SECTION_HEADER>& section_headers){
    for (auto& section : section_headers) {
        if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.Misc.VirtualSize) {
            return (rva - section.VirtualAddress) + section.PointerToRawData;
        }
    }
    return 0;
}

void print_dos_header(IMAGE_DOS_HEADER* h){
    cout << "---------- DOS HEADER ----------" << endl;
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
    cout << "------------------------------------" << endl;
}

void print_dos_stub(vector<char>& stubData){
    cout << "---------- DOS Stub ----------" << endl;
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
    cout << "------------------------------------" << endl;
}

void print_nt_header(IMAGE_NT_HEADERS32* h){
    cout << "---------- NT Header ----------" << endl;
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
    cout << "------------------------------------" << endl;

}

void print_section_header(const IMAGE_SECTION_HEADER& h) {
    cout << "---------- Section Header ----------" << endl;
    cout << hex << uppercase << setfill('0');
    cout << "Name : " << h.Name;
    cout << "  (Hex : ";
    for (int i = 0; i < 8; ++i) {
        cout << setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(h.Name[i])) << " ";
    }
    cout << ")" << endl;
    cout << "Virtual Size : " << setw(8) << h.Misc.VirtualSize << endl;
    cout << "Virtual Address (RVA) : " << setw(8) << h.VirtualAddress << endl;
    cout << "Size of Raw Data : " << setw(8) << h.SizeOfRawData << endl;
    cout << "Pointer to Raw Data : " << setw(8) << h.PointerToRawData << endl;
    cout << "Pointer to Relocations : " << setw(8) << h.PointerToRelocations << endl;
    cout << "Pointer to Line Numbers : " << setw(8) << h.PointerToLinenumbers << endl;
    cout << "Number of Relocations : " << setw(8) << h.NumberOfRelocations << endl;
    cout << "Number of Line Numbers : " << setw(8) << h.NumberOfLinenumbers << endl;
    cout << "Characteristics : " << setw(8) << h.Characteristics << endl;
    cout << "------------------------------------" << endl;
}

vector<IMAGE_IMPORT_DESCRIPTOR>parse_idt(ifstream& fin, IMAGE_NT_HEADERS32* nt_header, vector<IMAGE_SECTION_HEADER>& section_headers){
    vector<IMAGE_IMPORT_DESCRIPTOR> arr;
    IMAGE_DATA_DIRECTORY import_dir = nt_header->OptionalHeader.DataDirectory[1];
    if(import_dir.VirtualAddress == 0){
        cout << "Import Table not found" << endl;
        return arr;
    }
    DWORD import_table_raw = RVAToRAW(import_dir.VirtualAddress, section_headers);
    if(import_table_raw == 0){
        cout << "Error: Can't convert RVA to RAW for Import Table" << endl;
        return arr;
    }
    IMAGE_IMPORT_DESCRIPTOR iid;
    DWORD cur = import_table_raw;
    while(true){
        fin.seekg(cur, ios::beg);
        fin.read(reinterpret_cast<char*>(&iid), sizeof(iid));
        if(iid.Name == 0 && iid.OriginalFirstThunk == 0){
            break;
        }
        arr.push_back(iid);
        cur += sizeof(iid);
    }
    return arr;
}

void print_idt(ifstream& fin, vector<IMAGE_IMPORT_DESCRIPTOR>& idt, vector<IMAGE_SECTION_HEADER>& section_headers){
    if (idt.empty()) {
        cout << "Fail or No IDT" << endl;
        return;
    }
    cout << "---------- IDT ----------" << endl;
    int count = 0;
    for (const auto& iid : idt){
        cout << "[Descriptor " << count++ << "]" << endl;
        cout << hex << uppercase << setfill('0');
        cout << "OriginalFirstThunk : " << setw(8) << iid.OriginalFirstThunk << endl;
        cout << "TimeDateStamp : " << setw(8) << iid.TimeDateStamp << endl;
        cout << "ForwarderChain : " << setw(8) << iid.ForwarderChain << endl;
        cout << "Name (RVA) : " << setw(8) << iid.Name;
        DWORD dll_name_raw = RVAToRAW(iid.Name, section_headers);
        if (dll_name_raw != 0) {
            string dll_name;
            fin.clear();
            fin.seekg(dll_name_raw, ios::beg);
            getline(fin, dll_name, '\0');
            cout << " | DLL : " << dll_name << endl;
        }
        cout << "FirstThunk : " << setw(8) << iid.FirstThunk << endl;
    }
    cout << "------------------------------------" << endl;
}

typedef struct DLLThunks {
    string dll_name;
    DWORD int_rva;
    DWORD iat_rva;
    vector<IMAGE_THUNK_DATA32> int_thunks;
    vector<IMAGE_THUNK_DATA32> iat_thunks;
}DLLThunks;

vector<DLLThunks>parse_iat_int(ifstream& fin, vector<IMAGE_IMPORT_DESCRIPTOR>& idt, vector<IMAGE_SECTION_HEADER>& section_headers){
    vector<DLLThunks> arr;
    if (idt.empty()) return arr;
    for(auto& iid : idt){
        fin.clear();
        DLLThunks current_dll;
        DWORD dll_name_raw = RVAToRAW(iid.Name, section_headers);
        if (dll_name_raw != 0){
            fin.seekg(dll_name_raw, ios::beg);
            getline(fin, current_dll.dll_name, '\0');
        }
        current_dll.int_rva = iid.OriginalFirstThunk;
        current_dll.iat_rva = iid.FirstThunk;
        DWORD int_raw = RVAToRAW(iid.OriginalFirstThunk, section_headers);
        if (int_raw != 0){
            IMAGE_THUNK_DATA32 thunk;
            DWORD current_pos = int_raw;
            while (true){
                fin.seekg(current_pos, ios::beg);
                fin.read(reinterpret_cast<char*>(&thunk), sizeof(thunk));
                if (thunk.u1.AddressOfData == 0) break;
                current_dll.int_thunks.push_back(thunk);
                current_pos += sizeof(thunk);
            }
        }
        DWORD iat_raw = RVAToRAW(iid.FirstThunk, section_headers);
        if (iat_raw != 0){
            IMAGE_THUNK_DATA32 thunk;
            DWORD current_pos = iat_raw;
            while (true){
                fin.seekg(current_pos, ios::beg);
                fin.read(reinterpret_cast<char*>(&thunk), sizeof(thunk));
                 if (thunk.u1.AddressOfData == 0) break;
                current_dll.iat_thunks.push_back(thunk);
                current_pos += sizeof(thunk);
            }
        }
        arr.push_back(current_dll);
    }
    return arr;
}

void print_int(ifstream& fin, vector<DLLThunks>& thunk_data, vector<IMAGE_SECTION_HEADER>& section_headers, DWORD image_base){
    if(thunk_data.empty()){
        cout << "Error : There is no data" << endl;
        return;
    }
    cout << "---------- INT ----------" << endl;
    for(auto& dll_info : thunk_data){
        cout << "\nDLL: " << dll_info.dll_name << endl;
        cout << left;
        cout << setw(12) << "VA" << setw(12) << "Data" << setw(8) << "Hint" << "Function Name" << endl;
        cout << "-----------------------------------------------------------------" << endl;
        for(size_t i = 0; i < dll_info.int_thunks.size(); ++i){
            const auto& thunk = dll_info.int_thunks[i];
            DWORD current_rva = dll_info.int_rva + (i * sizeof(IMAGE_THUNK_DATA32));
            DWORD current_va = image_base + current_rva;
            cout << hex << uppercase << left;
            cout << setw(12) << current_va;
            cout << setw(12) << thunk.u1.AddressOfData;
            if(IMAGE_SNAP_BY_ORDINAL32(thunk.u1.Ordinal)){
                cout << setw(8) << "N/A" << "Ordinal: " << dec << (thunk.u1.Ordinal & 0xFFFF) << endl;
            } 
            else{
                DWORD name_rva = thunk.u1.AddressOfData;
                DWORD name_raw = RVAToRAW(name_rva, section_headers);
                if(name_raw != 0){
                    WORD hint;
                    string func_name;
                    fin.clear();
                    fin.seekg(name_raw, ios::beg);
                    fin.read(reinterpret_cast<char*>(&hint), sizeof(hint));
                    getline(fin, func_name, '\0');
                    cout << hex << setw(8) << hint << func_name << endl;
                }
            }
        }
        cout << left << setw(12) << "0" << setw(12) << "0" << "End of Imports" << endl;
    }
    cout << "------------------------------------" << endl;
}
void print_iat(ifstream& fin, vector<DLLThunks>& thunk_data, vector<IMAGE_SECTION_HEADER>& section_headers, DWORD image_base){
    if(thunk_data.empty()){
        cout << "Error : There is no data" << endl;
        return;
    }
    cout << "---------- IAT ----------" << endl;
    for(auto& dll_info : thunk_data){
        cout << "\nDLL: " << dll_info.dll_name << endl;
        cout << left;
        cout << setw(12) << "VA" << setw(12) << "Data" << "Description" << endl;
        cout << "-----------------------------------------------------------------" << endl;

        for(size_t i = 0; i < dll_info.iat_thunks.size(); ++i){
            const auto& iat_thunk = dll_info.iat_thunks[i];
            const auto& int_thunk_for_name = dll_info.int_thunks[i];
            DWORD current_rva = dll_info.iat_rva + (i * sizeof(IMAGE_THUNK_DATA32));
            DWORD current_va = image_base + current_rva; // VA 계산
            
            cout << hex << uppercase << left;
            cout << setw(12) << current_va;
            cout << setw(12) << iat_thunk.u1.AddressOfData;

            if(IMAGE_SNAP_BY_ORDINAL32(int_thunk_for_name.u1.Ordinal)){
                cout << "Ordinal: " << dec << (int_thunk_for_name.u1.Ordinal & 0xFFFF) << endl;
            } 
            else{
                DWORD name_rva = int_thunk_for_name.u1.AddressOfData;
                DWORD name_raw = RVAToRAW(name_rva, section_headers);
                if(name_raw != 0){
                    string func_name;
                    fin.clear();
                    fin.seekg(name_raw + sizeof(WORD), ios::beg);
                    getline(fin, func_name, '\0');
                    cout << func_name << endl;
                }
            }
        }
        cout << left << setw(12) << "0" << setw(12) << "0" << "End of Imports" << endl;
    }
    cout << "------------------------------------" << endl;
}

void print_eat_header(const IMAGE_EXPORT_DIRECTORY& eat_header, const string& dll_name){
    if (dll_name.empty()) {
        cout << "Parsing Error or No Table" << endl;
        return;
    }
    cout << hex << uppercase;
    cout << "---------- EAT Header ----------" << endl;
    cout << "DLL Name : " << dll_name << endl;
    cout << "Characteristics : " << eat_header.Characteristics << endl;
    cout << "TimeDateStamp : " << eat_header.TimeDateStamp << endl;
    cout << "Major/Minor Version : " << eat_header.MajorVersion << "/" << eat_header.MinorVersion << endl;
    cout << "Base : " << eat_header.Base << endl;
    cout << "NumberOfFunctions : " << eat_header.NumberOfFunctions << endl;
    cout << "NumberOfNames : " << eat_header.NumberOfNames << endl;
    cout << "AddressOfFunctions (RVA) : " << eat_header.AddressOfFunctions << endl;
    cout << "AddressOfNames (RVA) : " << eat_header.AddressOfNames << endl;
    cout << "AddressOfNameOrdinals (RVA) : " << eat_header.AddressOfNameOrdinals << endl;
    cout << "------------------------------------" << endl;
}

int main(){
    logo_start();
    // File Open
    string file_name;
    ifstream fin;
    while(1){
        cout << "Input File Name(-1 to exit) : ";
        cin >> file_name;
        if(file_name == "-1"){
            return 0;
        }
        fin.open(file_name, ios::binary);
        if(!fin){
            cout << "File Open Error : Please write once more" << endl;
            fin.clear();
        }
        else{
            break;
        }
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
    // Read Section Header
    vector<IMAGE_SECTION_HEADER> section_headers;
    fin.seekg(dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS32), ios::beg);
    int NumberOfSections = nt_header.FileHeader.NumberOfSections;
    section_headers.resize(NumberOfSections);
    fin.read(reinterpret_cast<char*>(section_headers.data()), sizeof(IMAGE_SECTION_HEADER) * NumberOfSections);
    if (fin.fail()) {
        cout << "Error: Can't read Section Headers" << endl;
        fin.close();
        return 1;
    }
    // IAT
    vector<IMAGE_IMPORT_DESCRIPTOR> idt = parse_idt(fin, &nt_header, section_headers);
    vector<DLLThunks> thunk_data = parse_iat_int(fin, idt, section_headers);
    // EAT
    IMAGE_EXPORT_DIRECTORY eat_header;
    string eat_dll_name;
    IMAGE_DATA_DIRECTORY export_dir_entry = nt_header.OptionalHeader.DataDirectory[0];
    if(export_dir_entry.VirtualAddress != 0){
        DWORD eat_raw = RVAToRAW(export_dir_entry.VirtualAddress, section_headers);
        if (eat_raw != 0){
            fin.clear();
            fin.seekg(eat_raw, ios::beg);
            fin.read(reinterpret_cast<char*>(&eat_header), sizeof(IMAGE_EXPORT_DIRECTORY));
            DWORD dll_name_raw = RVAToRAW(eat_header.Name, section_headers);
            fin.seekg(dll_name_raw, ios::beg);
            getline(fin, eat_dll_name, '\0');
        }
    }
    // Run Command
    int command;
    while(1){
        print_menu();
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
            case 4:{
                if (section_headers.empty()){
                    cout << "No sections found" << endl;
                    break;
                }
                cout << "--- Section List ---" << endl;
                for (size_t i = 0; i < section_headers.size(); ++i) {
                    cout << i + 1 << ". " << section_headers[i].Name << endl;
                }
                int sel;
                cout << "Select number : ";
                cin >> sel;
                if (sel > 0 && sel <= section_headers.size()) {
                    print_section_header(section_headers[sel - 1]);
                } else {
                    cout << "Invalid section number" << endl;
                }
                break;
            }
            case 5:
                print_idt(fin, idt, section_headers);
                break;
            case 6:
                print_int(fin, thunk_data, section_headers, nt_header.OptionalHeader.ImageBase);
                break;
            case 7:
                print_iat(fin, thunk_data, section_headers, nt_header.OptionalHeader.ImageBase);
                break;
            case 8:
                print_eat_header(eat_header, eat_dll_name);
                break;
            case 0:
                fin.close();
                cout << "Program Exit" << endl;
                return 0;
            default:
                cout << "Invalid command" << endl;
                break;
        }
    }
}