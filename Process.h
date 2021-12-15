#ifndef PROJECT_PROCESS_H
#define PROJECT_PROCESS_H

#define NOMINMAX
#include <iostream>
#include <list>
#include <string>
#include <vector>

#include <Aclapi.h>
#include <tlhelp32.h>
#include <Sddl.h>
#include <psapi.h>
#include <Winternl.h>
#include <cstdio>
#include <imagehlp.h>
#pragma comment(lib,"Version.lib")

#include "Integrity.h"

typedef BOOL(WINAPI* is64Process) (HANDLE, PBOOL);
using wlist = std::list<std::wstring>;

struct LANGANDCODEPAGE {
    WORD wLanguage;
    WORD wCodePage;
};

const std::string undef("Undefined");

class Process {
    std::wstring name = std::wstring(undef.begin(), undef.end());
    std::wstring path = std::wstring(undef.begin(), undef.end());
    std::wstring parentName = std::wstring(undef.begin(), undef.end());
    std::wstring ownerName = std::wstring(undef.begin(), undef.end());
    std::wstring SID_ = std::wstring(undef.begin(), undef.end());
    std::wstring environment = std::wstring(undef.begin(), undef.end());

    DWORD parentPID_;
    DWORD PID_;

    bool flagDEP;
    bool flagASLR;

    processType pType_;
    integrity integrity_;

    wlist dllList;
    wlist description;
    std::list<std::string> privileges;

    void GetDllList();
    void GetDescription();
    void GetPrivileges();

    std::wstring pType() const;
    std::wstring Integrity() const;
public:
    Process(DWORD ProcessID, DWORD ParentID, wchar_t* exeFile);

    std::wstring Name() const { return name; };
    std::wstring About() const;
    std::wstring jsonAbout() const;

    unsigned SetIntegrity(integrity newInt);
    unsigned SetPrivileges(const std::string& lpszPrivilege, bool bEnablePrivilege);
};

std::wstring GetPathToFile(HANDLE hProcess);
std::wstring GetParentName(HANDLE hProcess);
processType GetProcessType(HANDLE hProcess);
std::pair<std::wstring, std::wstring> GetOwnerAndSID(HANDLE hProcess);
integrity GetProcessIntegrity(HANDLE hProcess);
bool GetDEPofProcess(HANDLE hProcess);
bool GetASLRofProcess(HANDLE hProcess);
std::string GetPrivileges(DWORD processID);
#endif //PROJECT_PROCESS_H
