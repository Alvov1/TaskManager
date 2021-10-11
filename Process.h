#ifndef PROJECT_PROCESS_H
#define PROJECT_PROCESS_H

#define NOMINMAX
#include <iostream>
#include <windows.h>
#include <list>
#include <string>

typedef BOOL(WINAPI* is64Process) (HANDLE, PBOOL);
using wlist = std::list<std::wstring>;

enum processType { x32, x64 };
enum integrity { Low, Medium, High, System };

const std::string undef("Undefined");

class Process {
    wlist dllList;
    wlist definitions;
    wlist descriptors;

    std::wstring name = std::wstring(undef.begin(), undef.end());
    std::wstring path = std::wstring(undef.begin(), undef.end());
    std::wstring parentName = std::wstring(undef.begin(), undef.end());
    std::wstring ownerName = std::wstring(undef.begin(), undef.end());
    std::wstring SID_ = std::wstring(undef.begin(), undef.end());

    DWORD parentPID_;
    DWORD PID_;

    bool flagDEP;
    bool flagASLR;

    processType pType_;
    integrity integrity_;

public:
    Process(DWORD ProcessID, DWORD ParentID, wchar_t* exeFile);

    std::wstring Name() const;
    std::wstring Path() const;
    std::wstring ParentName() const;
    std::wstring OwnerName() const;
    std::wstring SID() const;
    wlist listDLL() const;
    wlist Definitions() const;
    wlist Descriptors() const;
    DWORD PID() const;
    DWORD ParentPID() const;
    processType pType() const;
    integrity Integrity() const;
    bool isDEP() const;
    bool isASLR() const;

    unsigned SetPath();
    unsigned SetParentName();
    unsigned SetProcessType();
    unsigned SetOwnerAndSID();
    unsigned SetIntegrity();
    unsigned SetDEP();
    unsigned SetASLR();
};

std::wstring GetPathToFile(HANDLE hProcess);
std::wstring GetParentName(HANDLE hProcess);
processType GetProcessType(HANDLE hProcess);
std::pair<std::wstring, std::wstring> GetOwnerAndSID(HANDLE hProcess);
integrity GetProcessIntegrity(HANDLE hProcess);
bool GetDEPofProcess(HANDLE hProcess);
bool GetASLRofProcess(HANDLE hProcess);
#endif //PROJECT_PROCESS_H
