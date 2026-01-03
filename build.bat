@echo off
g++ main.cpp -o PEViewer_32bit.exe
g++ main_gui.cpp -o "PEViewer(GUI)_32bit.exe" -lgdi32 -lcomdlg32 -mwindows
pause