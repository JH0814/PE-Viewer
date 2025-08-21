#include<iostream>
#include<string>
#include<windows.h>
#include<fstream>
#include <iomanip>
#include <vector>
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
    cout << "Offset to New EXE Header : " << setw(4) << h->e_lfanew << endl;
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

int main(){
    string file_name;
    cout << "Input File Name : ";
    cin >> file_name;
    ifstream fin;
    fin.open(file_name, ios::binary);
    if(!fin){
        cout << "File Open Error" << endl;
        return 1;
    }
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
    print_dos_header(&dos_header);
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
    fin.close();
}