#include<windows.h>
#include<commdlg.h>
#include<string>
#include<vector>
#include<sstream>
#include<iomanip>
#include<fstream>
using namespace std;
#define ID_FILE_OPEN    1001
#define ID_FILE_EXIT    1002
#define ID_VIEW_DOS     2001
#define ID_VIEW_NT      2002
#define ID_VIEW_SECTION 2003
#define ID_VIEW_IAT     2004
#define ID_VIEW_EAT     2005

HWND hEdit;
string cur_Filepath = "";

typedef struct DLLThunks {
    string dll_name;
    DWORD int_rva;
    DWORD iat_rva;
    vector<IMAGE_THUNK_DATA32> int_thunks;
    vector<IMAGE_THUNK_DATA32> iat_thunks;
}DLLThunks;

DWORD RVAToRAW(DWORD rva, vector<IMAGE_SECTION_HEADER>& section_headers){
    for (auto& section : section_headers) {
        if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.Misc.VirtualSize) {
            return (rva - section.VirtualAddress) + section.PointerToRawData;
        }
    }
    return 0;
}

bool OpenPE(HWND hwnd){
    OPENFILENAMEA ofn;
    char szFile[260] = {0};
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "PE Files (EXE, DLL)\0*.exe;*.dll\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if(GetOpenFileNameA(&ofn) == TRUE){
        cur_Filepath = ofn.lpstrFile;

        string title = "PE Viewer(GUI Ver) - " + cur_Filepath;
        SetWindowTextA(hwnd, title.c_str());

        string msg = "File loaded\r\nPath : " + cur_Filepath + "\r\n\r\nClick [View] if you want to watch info";
        SetWindowTextA(hEdit, msg.c_str());
        return true;
    }
    return false;
}

string GetDosHeaderString(string filepath){
    ifstream fin(filepath, ios::binary);
    if(!fin) return "Error : Cannot open file";
    IMAGE_DOS_HEADER dos_header;
    fin.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));
    fin.close();
    if(dos_header.e_magic != IMAGE_DOS_SIGNATURE){
        return "Error : Invalid PE File";
    }
    stringstream ss;
    ss << "---------- DOS HEADER ----------" << "\r\n";
    ss << hex << uppercase << setfill('0');
    
    ss << "Signature                    : " << setw(4) << dos_header.e_magic << "\r\n";
    ss << "Bytes on Last Page of File   : " << setw(4) << dos_header.e_cblp << "\r\n";
    ss << "Pages in File                : " << setw(4) << dos_header.e_cp << "\r\n";
    ss << "Relocations                  : " << setw(4) << dos_header.e_crlc << "\r\n";
    ss << "Size of Header in Paragraphs : " << setw(4) << dos_header.e_cparhdr << "\r\n";
    ss << "Minimum Extra Paragraphs     : " << setw(4) << dos_header.e_minalloc << "\r\n";
    ss << "Maximum Extra Paragraphs     : " << setw(4) << dos_header.e_maxalloc << "\r\n";
    ss << "Initial SS                   : " << setw(4) << dos_header.e_ss << "\r\n";
    ss << "Initial SP                   : " << setw(4) << dos_header.e_sp << "\r\n";
    ss << "Checksum                     : " << setw(4) << dos_header.e_csum << "\r\n";
    ss << "Initial IP                   : " << setw(4) << dos_header.e_ip << "\r\n";
    ss << "Initial CS                   : " << setw(4) << dos_header.e_cs << "\r\n";
    ss << "Offset to Relocation Table   : " << setw(4) << dos_header.e_lfarlc << "\r\n";
    ss << "Overlay Number               : " << setw(4) << dos_header.e_ovno << "\r\n";
    
    for(int i = 0; i<4; i++){
        ss << "Reserved[" << i << "]                 : " << setw(4) << dos_header.e_res[i] << "\r\n";
    }
    
    ss << "OEM Identifier               : " << setw(4) << dos_header.e_oemid << "\r\n";
    ss << "OEM Information              : " << setw(4) << dos_header.e_oeminfo << "\r\n";
    
    for(int i = 0; i<10; i++){
        ss << "Reserved2[" << i << "]                : " << setw(4) << dos_header.e_res2[i] << "\r\n";
    }
    
    ss << "Offset to New EXE Header     : " << setw(8) << dos_header.e_lfanew << "\r\n";
    ss << "------------------------------------" << "\r\n";

    return ss.str();
}

string GetNtHeaderString(string filepath){
    ifstream fin(filepath, ios::binary);
    if (!fin) return "Error: Cannot open file.";

    IMAGE_DOS_HEADER dos_header;
    fin.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) return "Error: Invalid DOS Signature.";

    // NT Header 위치로 이동
    IMAGE_NT_HEADERS32 nt_header;
    fin.seekg(dos_header.e_lfanew, ios::beg);
    fin.read(reinterpret_cast<char*>(&nt_header), sizeof(IMAGE_NT_HEADERS32));

    if (nt_header.Signature != IMAGE_NT_SIGNATURE) return "Error: Invalid NT Signature.";

    stringstream ss;
    ss << "========== NT HEADER ==========\r\n\r\n";
    ss << hex << uppercase << setfill('0');

    ss << "[File Header]\r\n";
    ss << "Machine              : " << setw(4) << nt_header.FileHeader.Machine << "\r\n";
    ss << "Number of Sections   : " << setw(4) << nt_header.FileHeader.NumberOfSections << "\r\n";
    ss << "Time Date Stamp      : " << setw(8) << nt_header.FileHeader.TimeDateStamp << "\r\n";
    ss << "Ptr to Symbol Table  : " << setw(8) << nt_header.FileHeader.PointerToSymbolTable << "\r\n";
    ss << "Size of Optional Hdr : " << setw(4) << nt_header.FileHeader.SizeOfOptionalHeader << "\r\n";
    ss << "Characteristics      : " << setw(4) << nt_header.FileHeader.Characteristics << "\r\n\r\n";

    ss << "[Optional Header]\r\n";
    ss << "Magic                : " << setw(4) << nt_header.OptionalHeader.Magic << " (PE32)\r\n";
    ss << "Address of Entry Pnt : " << setw(8) << nt_header.OptionalHeader.AddressOfEntryPoint << "\r\n";
    ss << "Image Base           : " << setw(8) << nt_header.OptionalHeader.ImageBase << "\r\n";
    ss << "Section Alignment    : " << setw(8) << nt_header.OptionalHeader.SectionAlignment << "\r\n";
    ss << "File Alignment       : " << setw(8) << nt_header.OptionalHeader.FileAlignment << "\r\n";
    ss << "Size of Image        : " << setw(8) << nt_header.OptionalHeader.SizeOfImage << "\r\n";
    ss << "Size of Headers      : " << setw(8) << nt_header.OptionalHeader.SizeOfHeaders << "\r\n";
    ss << "Subsystem            : " << setw(4) << nt_header.OptionalHeader.Subsystem << "\r\n";
    ss << "Num of Data Direct.  : " << setw(8) << nt_header.OptionalHeader.NumberOfRvaAndSizes << "\r\n";
    ss << "-------------------------------";

    return ss.str();
}

string GetSectionHeadersString(string filepath) {
    ifstream fin(filepath, ios::binary);
    if (!fin) return "Error: Cannot open file.";

    IMAGE_DOS_HEADER dos_header;
    fin.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));

    IMAGE_NT_HEADERS32 nt_header;
    fin.seekg(dos_header.e_lfanew, ios::beg);
    fin.read(reinterpret_cast<char*>(&nt_header), sizeof(IMAGE_NT_HEADERS32));

    int numberOfSections = nt_header.FileHeader.NumberOfSections;
    vector<IMAGE_SECTION_HEADER> sections(numberOfSections);

    // 섹션 헤더는 NT 헤더 바로 뒤에 이어집니다.
    fin.read(reinterpret_cast<char*>(sections.data()), sizeof(IMAGE_SECTION_HEADER) * numberOfSections);

    stringstream ss;
    ss << "========== SECTION HEADERS (" << dec << numberOfSections << ") ==========\r\n\r\n";
    ss << hex << uppercase << setfill('0');

    for (int i = 0; i < numberOfSections; i++) {
        ss << "[" << dec << (i + 1) << "] Name : " << sections[i].Name << "\r\n";
        ss << "    Virtual Size     : " << setw(8) << sections[i].Misc.VirtualSize << "\r\n";
        ss << "    Virtual Address  : " << setw(8) << sections[i].VirtualAddress << " (RVA)\r\n";
        ss << "    Size of Raw Data : " << setw(8) << sections[i].SizeOfRawData << "\r\n";
        ss << "    Ptr to Raw Data  : " << setw(8) << sections[i].PointerToRawData << "\r\n";
        ss << "    Characteristics  : " << setw(8) << sections[i].Characteristics << "\r\n";
        ss << "------------------------------------------\r\n";
    }

    return ss.str();
}

string GetIATString(string filepath){
    ifstream fin(filepath, ios::binary);
    if (!fin) return "Error: Cannot open file.";

    IMAGE_DOS_HEADER dos_header;
    fin.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));

    IMAGE_NT_HEADERS32 nt_header;
    fin.seekg(dos_header.e_lfanew, ios::beg);
    fin.read(reinterpret_cast<char*>(&nt_header), sizeof(IMAGE_NT_HEADERS32));

    int numberOfSections = nt_header.FileHeader.NumberOfSections;
    vector<IMAGE_SECTION_HEADER> sections(numberOfSections);
    fin.read(reinterpret_cast<char*>(sections.data()), sizeof(IMAGE_SECTION_HEADER) * numberOfSections);

    IMAGE_DATA_DIRECTORY import_dir = nt_header.OptionalHeader.DataDirectory[1];
    if (import_dir.VirtualAddress == 0) return "Import Table not found.";

    DWORD import_table_raw = RVAToRAW(import_dir.VirtualAddress, sections);
    if (import_table_raw == 0) return "Error: Invalid Import Table Address.";

    stringstream ss;
    ss << "========== IMPORT ADDRESS TABLE (IAT) ==========\r\n\r\n";

    fin.seekg(import_table_raw, ios::beg);
    IMAGE_IMPORT_DESCRIPTOR iid;
    DWORD current_descriptor_pos = import_table_raw;

    while (true) {
        fin.seekg(current_descriptor_pos, ios::beg);
        fin.read(reinterpret_cast<char*>(&iid), sizeof(iid));
        
        if (iid.Name == 0 && iid.OriginalFirstThunk == 0) break;

        string dll_name = "Unknown";
        DWORD name_raw = RVAToRAW(iid.Name, sections);
        if (name_raw != 0) {
            fin.seekg(name_raw, ios::beg);
            getline(fin, dll_name, '\0');
        }

        ss << "[ DLL: " << dll_name << " ]\r\n";
        ss << "------------------------------------------------------------\r\n";
        ss << left << setw(12) << "RVA" << setw(12) << "Data" << "Function Name / Ordinal" << "\r\n";
        ss << "------------------------------------------------------------\r\n";

        DWORD thunk_rva = (iid.OriginalFirstThunk != 0) ? iid.OriginalFirstThunk : iid.FirstThunk;
        DWORD thunk_raw = RVAToRAW(thunk_rva, sections);
        
        if (thunk_raw != 0) {
            IMAGE_THUNK_DATA32 thunk;
            DWORD current_thunk_pos = thunk_raw;

            while (true) {
                fin.seekg(current_thunk_pos, ios::beg);
                fin.read(reinterpret_cast<char*>(&thunk), sizeof(thunk));

                if (thunk.u1.AddressOfData == 0) break;

                ss << hex << uppercase << setw(12) << thunk_rva << setw(12) << thunk.u1.AddressOfData;

                if (IMAGE_SNAP_BY_ORDINAL32(thunk.u1.Ordinal)) {
                    ss << "Ordinal: " << dec << (thunk.u1.Ordinal & 0xFFFF) << "\r\n";
                } else {
                    DWORD func_name_raw = RVAToRAW(thunk.u1.AddressOfData, sections);
                    if (func_name_raw != 0) {
                        fin.seekg(func_name_raw + 2, ios::beg);
                        string func_name;
                        getline(fin, func_name, '\0');
                        ss << func_name << "\r\n";
                    } else {
                        ss << "Invalid Name RVA\r\n";
                    }
                }
                current_thunk_pos += sizeof(IMAGE_THUNK_DATA32);
                thunk_rva += sizeof(IMAGE_THUNK_DATA32);
            }
        }
        ss << "\r\n";
        current_descriptor_pos += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    
    return ss.str();
}

string GetEATString(string filepath){
    ifstream fin(filepath, ios::binary);
    if (!fin) return "Error: Cannot open file.";

    IMAGE_DOS_HEADER dos_header;
    fin.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));
    IMAGE_NT_HEADERS32 nt_header;
    fin.seekg(dos_header.e_lfanew, ios::beg);
    fin.read(reinterpret_cast<char*>(&nt_header), sizeof(IMAGE_NT_HEADERS32));
    
    int numberOfSections = nt_header.FileHeader.NumberOfSections;
    vector<IMAGE_SECTION_HEADER> sections(numberOfSections);
    fin.read(reinterpret_cast<char*>(sections.data()), sizeof(IMAGE_SECTION_HEADER) * numberOfSections);

    IMAGE_DATA_DIRECTORY export_dir = nt_header.OptionalHeader.DataDirectory[0];
    if (export_dir.VirtualAddress == 0) return "Export Table not found (This file may not be a DLL).";

    DWORD eat_raw = RVAToRAW(export_dir.VirtualAddress, sections);
    if (eat_raw == 0) return "Error: Invalid Export Table Address.";

    IMAGE_EXPORT_DIRECTORY eat;
    fin.seekg(eat_raw, ios::beg);
    fin.read(reinterpret_cast<char*>(&eat), sizeof(eat));

    string dll_name = "Unknown";
    DWORD name_raw = RVAToRAW(eat.Name, sections);
    if (name_raw != 0) {
        fin.seekg(name_raw, ios::beg);
        getline(fin, dll_name, '\0');
    }

    stringstream ss;
    ss << "========== EXPORT ADDRESS TABLE (EAT) ==========\r\n\r\n";
    ss << "DLL Name           : " << dll_name << "\r\n";
    ss << "Base               : " << eat.Base << "\r\n";
    ss << "Number of Functions: " << eat.NumberOfFunctions << "\r\n";
    ss << "Number of Names    : " << eat.NumberOfNames << "\r\n";
    ss << "Address of Funcs   : " << hex << uppercase << eat.AddressOfFunctions << "\r\n";
    ss << "Address of Names   : " << eat.AddressOfNames << "\r\n\r\n";

    ss << "--------------------------------------------------\r\n";
    ss << left << setw(10) << "Ordinal" << setw(12) << "RVA" << "Function Name" << "\r\n";
    ss << "--------------------------------------------------\r\n";

    if (eat.NumberOfNames > 0 && eat.AddressOfNames != 0) {
        DWORD names_start_raw = RVAToRAW(eat.AddressOfNames, sections);
        DWORD ordinals_start_raw = RVAToRAW(eat.AddressOfNameOrdinals, sections);
        DWORD func_start_raw = RVAToRAW(eat.AddressOfFunctions, sections);

        for (DWORD i = 0; i < eat.NumberOfNames; i++) {
            DWORD name_rva;
            fin.seekg(names_start_raw + i * 4, ios::beg);
            fin.read(reinterpret_cast<char*>(&name_rva), sizeof(name_rva));

            WORD ordinal;
            fin.seekg(ordinals_start_raw + i * 2, ios::beg);
            fin.read(reinterpret_cast<char*>(&ordinal), sizeof(ordinal));

            DWORD func_rva;
            fin.seekg(func_start_raw + ordinal * 4, ios::beg); 
            fin.read(reinterpret_cast<char*>(&func_rva), sizeof(func_rva));

            string func_name;
            DWORD str_raw = RVAToRAW(name_rva, sections);
            if (str_raw != 0) {
                fin.seekg(str_raw, ios::beg);
                getline(fin, func_name, '\0');
            }

            ss << hex << uppercase << setw(10) << (eat.Base + ordinal) << setw(12) << func_rva << func_name << "\r\n";
        }
    }

    return ss.str();
}

// 윈도우 메시지 처리 함수 (이벤트 처리기)
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        hEdit = CreateWindowA("EDIT", NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY, 0, 0, 0, 0, hwnd, (HMENU)1, GetModuleHandleA(NULL), NULL);
        SendMessage(hEdit, WM_SETFONT, (WPARAM)GetStockObject(ANSI_FIXED_FONT), TRUE);
        break;

    case WM_SIZE:
        MoveWindow(hEdit, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE);
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_FILE_OPEN:
            OpenPE(hwnd);
            break;
        case ID_VIEW_DOS:
            if(cur_Filepath.empty()){
                MessageBoxA(hwnd, "Open File first", "alert", MB_OK | MB_ICONINFORMATION);
            }
            else{
                string res = GetDosHeaderString(cur_Filepath);
                SetWindowTextA(hEdit, res.c_str());
            }
            break;
        case ID_VIEW_NT:
            if(cur_Filepath.empty()){
                MessageBoxA(hwnd, "Open File first", "alert", MB_OK | MB_ICONINFORMATION);
            }
            else{
                string result = GetNtHeaderString(cur_Filepath);
                SetWindowTextA(hEdit, result.c_str());
            }
            break;
        case ID_FILE_EXIT:
            PostQuitMessage(0);
            break;
        case ID_VIEW_SECTION:
            if(cur_Filepath.empty()){
                MessageBoxA(hwnd, "Open File first", "alert", MB_OK | MB_ICONINFORMATION);
            }
            else{
                string result = GetSectionHeadersString(cur_Filepath);
                SetWindowTextA(hEdit, result.c_str());
            }
            break;
        case ID_VIEW_IAT:
            if(cur_Filepath.empty()){
                MessageBoxA(hwnd, "Open File first", "alert", MB_OK | MB_ICONINFORMATION);
            }
            else{
                string result = GetIATString(cur_Filepath);
                SetWindowTextA(hEdit, result.c_str());
            }
            break;
        case ID_VIEW_EAT:
            if(cur_Filepath.empty()){
                MessageBoxA(hwnd, "Open File first", "alert", MB_OK | MB_ICONINFORMATION);
            }
            else{
                string result = GetEATString(cur_Filepath);
                SetWindowTextA(hEdit, result.c_str());
            }
            break;
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow){
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "PEViewerGUI";
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowA("PEViewerGUI", "PE Viewer(GUI Ver)",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        NULL, NULL, hInstance, NULL);
    
    // Menu 생성
    HMENU hMenu = CreateMenu();

    // [File] 메뉴
    HMENU hFileMenu = CreateMenu();
    AppendMenuA(hFileMenu, MF_STRING, ID_FILE_OPEN, "Open File");
    AppendMenuA(hFileMenu, MF_SEPARATOR, 0, NULL); // 구분선
    AppendMenuA(hFileMenu, MF_STRING, ID_FILE_EXIT, "Exit");
    AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, "File");

    // [View] 메뉴
    HMENU hViewMenu = CreateMenu();
    AppendMenuA(hViewMenu, MF_STRING, ID_VIEW_DOS, "DOS Header");
    AppendMenuA(hViewMenu, MF_STRING, ID_VIEW_NT, "NT Header");
    AppendMenuA(hViewMenu, MF_STRING, ID_VIEW_SECTION, "Section Headers");
    AppendMenuA(hViewMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hViewMenu, MF_STRING, ID_VIEW_IAT, "Import Table(IAT)");
    AppendMenuA(hViewMenu, MF_STRING, ID_VIEW_EAT, "Export Table(EAT)");
    AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hViewMenu, "View");

    SetMenu(hwnd, hMenu); // 윈도우에 메뉴 적용

    // 화면 표시
    ShowWindow(hwnd, nCmdShow);

    // 메시지 루프
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}
