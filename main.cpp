#include<iostream>
#include<string>
#include<windows.h>
#include<fstream>
using namespace std;

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
    fin.close();
}