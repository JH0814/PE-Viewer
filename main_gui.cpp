#include<windows.h>
#define ID_FILE_OPEN    1001
#define ID_FILE_EXIT    1002
#define ID_VIEW_DOS     2001
#define ID_VIEW_NT      2002
#define ID_VIEW_SECTION 2003
#define ID_VIEW_IAT     2004
#define ID_VIEW_EAT     2005

HWND hEdit;

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
            SetWindowTextA(hEdit, "File -> Open 메뉴가 클릭되었습니다.\r\n파일 선택창이 뜰 예정입니다.");
            break;
        case ID_VIEW_DOS:
            SetWindowTextA(hEdit, "View -> DOS Header 메뉴가 클릭되었습니다.\r\n여기에 DOS 헤더 정보가 출력됩니다.");
            break;
        case ID_VIEW_NT:
            SetWindowTextA(hEdit, "View -> NT Header 메뉴가 클릭되었습니다.");
            break;
        case ID_FILE_EXIT:
            PostQuitMessage(0);
            break;
        case ID_VIEW_SECTION:
            SetWindowTextA(hEdit, "View -> Section Headers 메뉴가 클릭되었습니다.\r\n섹션 정보가 여기에 출력됩니다.");
            break;
        case ID_VIEW_IAT:
            SetWindowTextA(hEdit, "View -> Import Table (IAT) 메뉴가 클릭되었습니다.");
            break;
        case ID_VIEW_EAT:
            SetWindowTextA(hEdit, "View -> Export Table (EAT) 메뉴가 클릭되었습니다.");
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
