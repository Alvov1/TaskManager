#define NOMINMAX
#include "mainwindow.h"
#include <iostream>
#include <list>
#include <windows.h>
#include <TlHelp32.h>
#include "Process.h"

#include <QApplication>


unsigned GenerateProcessList(std::list<Process>& list) {
    list.clear();

    auto* pEntry = new PROCESSENTRY32;
    pEntry->dwSize = sizeof(*pEntry);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if(snap != INVALID_HANDLE_VALUE) {
        for(auto i = Process32First(snap, pEntry); i; i = Process32Next(snap, pEntry))
            list.push_back(Process(pEntry->th32ProcessID, pEntry->th32ParentProcessID, pEntry->szExeFile));

        CloseHandle(snap);
        delete pEntry;
        return 0;
    }

    delete pEntry;
    return 1;
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    std::list<Process> ProcessList;
    GenerateProcessList(ProcessList);
    MainWindow w(ProcessList);
    w.show();
    return a.exec();
}
