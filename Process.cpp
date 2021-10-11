#include "Process.h"
#include <Psapi.h>
#include <sddl.h>
#include <Aclapi.h>

std::wstring Process::Name() const { return name; }
std::wstring Process::Path() const { return path; }
std::wstring Process::ParentName() const { return parentName; }
std::wstring Process::OwnerName() const { return ownerName; }
std::wstring Process::SID() const { return SID_; }
wlist Process::listDLL() const { return dllList; }
wlist Process::Definitions() const { return definitions; }
wlist Process::Descriptors() const { return descriptors; }
DWORD Process::PID() const { return PID_; }
DWORD Process::ParentPID() const { return parentPID_; }
processType Process::pType() const { return pType_; }
integrity Process::Integrity() const { return integrity_; }
bool Process::isDEP() const { return flagDEP; }
bool Process::isASLR() const { return flagASLR; }

/*  wlist dllList;
    wlist definitions;
    wlist descriptors;

    std::wstring name;          *
    std::wstring path;          *
    std::wstring parentName;    *
    std::wstring ownerName;     *
    std::wstring SID_;          *

    DWORD parentPID_;           *
    DWORD PID_;                 *

    bool flagDEP;               *
    bool flagASLR;              *

    processType pType_;         *
    integrity integrity_;       *
*/

std::wstring GetPathToFile(HANDLE hProcess) {
    wchar_t buffer[MAX_PATH] = {0};
    if(GetModuleFileNameEx(hProcess, nullptr, buffer, MAX_PATH))
        return std::wstring(buffer);
    else
        return std::wstring();
}
std::wstring GetParentName(HANDLE hProcess) {
    wchar_t buffer[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    if(QueryFullProcessImageName(hProcess, 0, buffer, &size)) {
        std::wstring temp(buffer);
        return temp.substr(temp.find_last_of(L'\\') + 1, std::wstring::npos);
    } else
        return std::wstring();
}
processType GetProcessType(HANDLE hProcess) {
    BOOL flag = FALSE;
    auto pFunction = reinterpret_cast <is64Process>(
            GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process"));
    if(pFunction != nullptr && pFunction(hProcess, &flag))
        return (flag ? x64 : x32);
    return x64;
}
std::pair<std::wstring, std::wstring> GetOwnerAndSID(HANDLE hProcess) {
    DWORD size = 0;
    if(OpenProcessToken(hProcess, TOKEN_READ, &hProcess))
        if(GetTokenInformation(hProcess, TokenUser, nullptr, size, &size) ||
           GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            auto pUserToken = (PTOKEN_USER) GlobalAlloc(GPTR, size);

            if(pUserToken != nullptr) {
                if(GetTokenInformation(hProcess, TokenUser, pUserToken, size, &size)) {
                    SID_NAME_USE snuSIDNameUse;
                    TCHAR szUser[MAX_PATH] = {0};
                    DWORD dwUserNameLength = MAX_PATH;
                    TCHAR szDomain[MAX_PATH] = {0};
                    DWORD dwDomainNameLength = MAX_PATH;

                    if(LookupAccountSid(nullptr, pUserToken->User.Sid, szUser, &dwUserNameLength, szDomain, &dwDomainNameLength, &snuSIDNameUse)) {
                        LPWSTR SID; // LPWSTR
                        if(ConvertSidToStringSid(pUserToken->User.Sid, &SID)) {
                            auto retValue = std::pair(std::wstring(reinterpret_cast<const wchar_t *const>(szUser)),
                                                      std::wstring(reinterpret_cast<const wchar_t *const>(SID)));
                            GlobalFree(pUserToken);
                            return retValue;
                        }
                    }
                }
            }

        }
    return std::pair(std::wstring(), std::wstring());
}
integrity GetProcessIntegrity(HANDLE hProcess) {
    HANDLE hToken;
    DWORD size;
    if(OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        DWORD integrity;
        PTOKEN_MANDATORY_LABEL pTIL = nullptr;
        if (GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &size) ||
            GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            pTIL = (PTOKEN_MANDATORY_LABEL) LocalAlloc(0, size);
            if (pTIL != nullptr)
                if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, size, &size)) {
                    integrity = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD) (UCHAR) (
                            *GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

                    if (integrity == SECURITY_MANDATORY_LOW_RID)
                        return Low;
                    else if (integrity >= SECURITY_MANDATORY_MEDIUM_RID &&
                             integrity < SECURITY_MANDATORY_HIGH_RID)
                        return Medium;
                    else if (integrity >= SECURITY_MANDATORY_HIGH_RID)
                        return High;
                    else if (integrity >= SECURITY_MANDATORY_SYSTEM_RID)
                        return System;
                }
        }
    }
    return Low;
}
bool GetDEPofProcess(HANDLE hProcess) {
    PROCESS_MITIGATION_DEP_POLICY depPolicy = PROCESS_MITIGATION_DEP_POLICY();
    if(GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &depPolicy, sizeof(depPolicy)))
        return true;
    else
        return false;
}
bool GetASLRofProcess(HANDLE hProcess) {
    PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = PROCESS_MITIGATION_ASLR_POLICY();
    if(GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy)))
        return true;
    else
        return false;
}

Process::Process(DWORD ProcessID, DWORD ParentID, wchar_t* exeFile)  :
        PID_(ProcessID), parentPID_(ParentID) {
    name = std::wstring(exeFile);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, PID_);
    if(hProcess != nullptr) {
        /* Getting path to the executable file of the process. */
        path = GetPathToFile(hProcess);

        /* Getting DEP flag of the process. */
        flagDEP = GetDEPofProcess(hProcess);

        /* Getting ALSR flag of the process. */
        flagASLR = GetASLRofProcess(hProcess);

        CloseHandle(hProcess);
    }

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, parentPID_);
    if(hProcess != nullptr) {
        /* Getting name of the parent process. */
        parentName = GetParentName(hProcess);

        /* Getting type of the process - 64 or 32. */
        pType_ = GetProcessType(hProcess);

        /* Getting process SID and owner's of the process name. */
        auto OwnerAndSID = GetOwnerAndSID(hProcess);
        ownerName = OwnerAndSID.first;
        SID_ = OwnerAndSID.second;

        CloseHandle(hProcess);
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, PID_);
    if(hProcess != nullptr) {
        /* Getting integrity of the process. */
        integrity_ = GetProcessIntegrity(hProcess);

        CloseHandle(hProcess);
    }

}

unsigned Process::SetPath() {
    return 0;
}

unsigned Process::SetParentName() {
    return 0;
}

unsigned Process::SetProcessType() {
    return 0;
}

unsigned Process::SetOwnerAndSID() {
    return 0;
}

unsigned Process::SetIntegrity() {
    return 0;
}

unsigned Process::SetDEP() {
    return 0;
}

unsigned Process::SetASLR() {
    return 0;
}
