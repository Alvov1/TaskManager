#include "Process.h"

std::wstring Process::pType() const {
    if (pType_ == x32)
        return {L"x32"};
    else
        return {L"x64"};
}
std::wstring Process::Integrity() const {
    switch (integrity_) {
        case Low:
            return {L"Low"};
        case Medium:
            return {L"Medium"};
        case High:
            return {L"High"};
        case System:
            return {L"System"};
        default:
            return {L"Undefined"};
    }
}
std::wstring GetPathToFile(HANDLE hProcess) {
    TCHAR buffer[MAX_PATH] = {0};
    if (GetModuleFileNameEx(hProcess, nullptr, buffer, MAX_PATH))
        return {reinterpret_cast<const wchar_t *const>(buffer)};
    else
        return {};
}
std::wstring GetParentName(HANDLE hProcess) {
    WCHAR buffer[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size)) {
        std::wstring temp(buffer);
        return temp.substr(temp.find_last_of(L'\\') + 1);
    } else
        return {};
}
processType GetProcessType(HANDLE hProcess) {
    BOOL flag = FALSE;
    auto pFunction = reinterpret_cast <is64Process>(
            GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process"));
    if (pFunction != nullptr && pFunction(hProcess, &flag))
        return (flag ? x64 : x32);
    return x64;
}
std::pair<std::wstring, std::wstring> GetOwnerAndSID(HANDLE hProcess) {
    DWORD size = 0;
    if (OpenProcessToken(hProcess, TOKEN_READ, &hProcess))
        if (GetTokenInformation(hProcess, TokenUser, nullptr, size, &size) ||
            GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            auto pUserToken = (PTOKEN_USER) GlobalAlloc(GPTR, size);

            if (pUserToken != nullptr && GetTokenInformation(hProcess, TokenUser, pUserToken, size, &size)) {
                SID_NAME_USE snuSIDNameUse;
                WCHAR szUser[MAX_PATH] = {0};
                DWORD dwUserNameLength = MAX_PATH;
                WCHAR szDomain[MAX_PATH] = {0};
                DWORD dwDomainNameLength = MAX_PATH;
                LPWSTR SID = nullptr;

                if (LookupAccountSidW(nullptr, pUserToken->User.Sid, szUser, &dwUserNameLength, szDomain,
                                      &dwDomainNameLength, &snuSIDNameUse))
                    if (ConvertSidToStringSidW(pUserToken->User.Sid, &SID)) {
                        GlobalFree(pUserToken);
                        return {{szUser},
                                {SID}};
                    }

            }
        }
    return {std::wstring(), std::wstring()};
}
integrity GetProcessIntegrity(HANDLE hProcess) {
    HANDLE hToken;
    DWORD size;
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
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
    if (GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &depPolicy, sizeof(depPolicy)))
        return true;
    else
        return false;
}
bool GetASLRofProcess(HANDLE hProcess) {
    PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = PROCESS_MITIGATION_ASLR_POLICY();
    if (GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy)))
        return true;
    else
        return false;
}
void Process::GetPrivileges() {
    DWORD dwSize = 0;
    PTOKEN_PRIVILEGES privelegesInfo = nullptr;
    char lpName[256] = {0};
    HANDLE hProcess = nullptr;
    HANDLE hToken = nullptr;

    if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, PID_)) != nullptr &&
        OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken) &&
        !GetTokenInformation(hToken, TokenPrivileges, nullptr, dwSize, &dwSize)) {
        privelegesInfo = (PTOKEN_PRIVILEGES) GlobalAlloc(GPTR, dwSize);

        if (GetTokenInformation(hToken, TokenPrivileges, privelegesInfo, dwSize, &dwSize) && privelegesInfo) {
            dwSize = 256;

            for (auto i = 0; i < privelegesInfo->PrivilegeCount; ++i)
                if (LookupPrivilegeNameA(nullptr, &privelegesInfo->Privileges[i].Luid, lpName, &dwSize))
                    privileges.emplace_back(lpName);
        }
    }

    if (privelegesInfo)
        GlobalFree(privelegesInfo);
    if (hProcess)
        CloseHandle(hProcess);
    if (hToken)
        CloseHandle(hToken);
}
void Process::GetDllList() {
    MODULEENTRY32 moduleInfo;
    moduleInfo.dwSize = sizeof(moduleInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID_);
    if (processesSnapshot != INVALID_HANDLE_VALUE) {
        for (BOOL bok = Module32First(processesSnapshot, &moduleInfo);
             bok; bok = Module32Next(processesSnapshot, &moduleInfo))
            dllList.emplace_back(moduleInfo.szModule);

        CloseHandle(processesSnapshot);
    }
}
void Process::GetDescription() {
    PLONG infoBuffer;
    DWORD infoSize;
    LANGANDCODEPAGE *pLangCodePage;
    WCHAR paramNameBuf[256];
    WCHAR *paramValue;
    UINT paramSz;

    static const std::vector<std::wstring> paramNames{
            {L"FileDescription"},
            {L"CompanyName"},
            {L"FileVersion"},
            {L"InternalName"},
            {L"LegalCopyright"},
            {L"LegalTradeMarks"},
            {L"OriginalFilename"},
            {L"ProductName"},
            {L"ProductVersion"},
            {L"Comments"},
            {L"Author"}
    };

    infoSize = GetFileVersionInfoSizeW(name.c_str(), nullptr);
    if (infoSize > 0) {
        infoBuffer = (PLONG) malloc(infoSize);
        UINT cpSz;

        if (GetFileVersionInfoW(name.c_str(), NULL, infoSize, infoBuffer) != 0 &&
        VerQueryValueW(infoBuffer, (L"\\VarFileInfo\\Translation"), (LPVOID *) &pLangCodePage, &cpSz)) {
            for (int cpIdx = 0; cpIdx < (int) (cpSz / sizeof(struct LANGANDCODEPAGE)); cpIdx++)
                for (auto &paramName: paramNames) {
                    wsprintfW(paramNameBuf, (L"\\StringFileInfo\\%04x%04x\\%s"),
                              pLangCodePage[cpIdx].wLanguage, pLangCodePage[cpIdx].wCodePage, paramName.c_str());

                    if (VerQueryValueW(infoBuffer, paramNameBuf, (LPVOID *) &paramValue, &paramSz))
                        description.emplace_back(paramName + L": " + paramValue);
                    else
                        description.emplace_back(paramName + L": No information");

                }
        }

        free(infoBuffer);
    }
}

Process::Process(DWORD ProcessID, DWORD ParentID, wchar_t *exeFile) :
        PID_(ProcessID), parentPID_(ParentID) {
    name = std::wstring(exeFile);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, PID_);
    if (hProcess != nullptr) {
        /* Getting path to the executable file of the process. */
        path = GetPathToFile(hProcess);

        /* Getting DEP flag of the process. */
        flagDEP = GetDEPofProcess(hProcess);

        /* Getting ALSR flag of the process. */
        flagASLR = GetASLRofProcess(hProcess);

        CloseHandle(hProcess);
    }

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, parentPID_);
    if (hProcess != nullptr) {
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
    if (hProcess != nullptr) {
        /* Getting integrity of the process. */
        integrity_ = GetProcessIntegrity(hProcess);

        CloseHandle(hProcess);
    }

    GetDllList();
    GetDescription();
    GetPrivileges();
}

std::wstring Process::About() const {
    std::wstring result;
    result.reserve(700);

    result += L"Name: " + std::wstring(name.begin(), name.end()) + L".\n";
    result += L"Description:\n";
    for (auto &definition: description)
        result += L"\t" + definition + L"\n";
    result += L"PID: " + std::to_wstring(PID_) + L".\n";
    result += L"Path: " + path + L".\n";
    result += L"Parent name: " + parentName + L". PID: " + std::to_wstring(parentPID_) + L".\n";
    result += L"Owner: " + ownerName + L". SID: " + SID_ + L".\n";
    result += L"Process type: " + pType() + L"\n";
    result += L"Runtime environment: " + environment + L"\n";
    result += L"Using DEP: ";
    result += (flagDEP ? L"True. Using ASLR: " : L"False. Using ASLR: ");
    result += (flagASLR ? L"True.\n" : L"False.\n");

    result += L"Using DLL's:\n";
    for (auto &dll: dllList)
        result += L"\t" + std::wstring(dll.begin(), dll.end()) + L"\n";

    result += L"\nIntegrity: " + Integrity() + L"\n";
    result += L"Privileges:\n";
    for(auto &priv: privileges)
        result += L"\t" + std::wstring(priv.begin(), priv.end()) + L"\n";

    return result;
}

template <typename listContent>
std::wstring writeList(const std::wstring& listName, const std::wstring& objName, const std::list<listContent>& list){
    std::wstring result = L"\"" + listName + L"\":[";
    if(!list.empty()) {
        result += L"{\"" + objName + L"\":\"" + std::wstring((*list.begin()).begin(), (*list.begin()).end()) + L"\"}";

        for (auto it = ++list.begin(); it != list.end(); ++it)
            result += L",{\"" + objName + L"\":\"" + std::wstring((*it).begin(), (*it).end()) + L"\"}";
    }
    result += L"],";
    return result;
}

std::wstring Process::jsonAbout() const {
    std::wstring result(L"{");
    result.reserve(700);

    result += L"\"Name\":\"" + name + L"\",";
    result += writeList( L"Descriptions", L"Description", description);
    result += L"\"PID\":\"" + std::to_wstring(PID_) + L"\",";
    result += L"\"Path\":\"" + path + L"\",";
    result += L"\"Parent name\":\"" + parentName + L"\",";
    result += L"\"Parent PID\":\"" + std::to_wstring(parentPID_) + L"\",";
    result += L"\"Owner name\":\"" + ownerName + L"\",";
    result += L"\"SID\":\"" + SID_ + L"\",";
    result += L"\"Process type\":\"" + pType() + L"\",";
    result += L"\"Runtime environment\":\"" + environment + L"\",";
    result += L"\"Using DEP\":\"" + std::to_wstring(flagDEP)+ L"\",";
    result += L"\"Using ASLR\":\"" + std::to_wstring(flagASLR)+ L"\",";
    result += writeList(L"Dlls", L"Dll", dllList);
    result += L"\"Integrity\":\"" + Integrity() + L"\",";
    result += writeList(L"Privileges", L"Privilege", privileges);
    result += L"}";

    return result;
}

unsigned Process::SetIntegrity(integrity newInt) {
    LPCWSTR SLowIntegritySid = L"S-1-16-4096";
    LPCWSTR SMediumIntegritySid = L"S-1-16-8192";
    LPCWSTR SHighIntegritySid = L"S-1-16-12288";
    LPCWSTR SSystemIntegritySid = L"S-1-16-16384";
    LPCWSTR wszIntegritySid;

    HANDLE hToken;
    HANDLE hNewToken;

    switch (newInt) {
        case Low:
            wszIntegritySid = SLowIntegritySid;
            break;
        case Medium:
            wszIntegritySid = SMediumIntegritySid;
            break;
        case High:
            wszIntegritySid = SHighIntegritySid;
            break;
        default:
            throw std::runtime_error("Unknown integrity level");
    }

    PSID pIntegritySid = NULL;
    TOKEN_MANDATORY_LABEL TIL = {0};
    TOKEN_MANDATORY_POLICY POL = {0};

    if (OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken)) {
        if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                             SecurityImpersonation, TokenPrimary, &hNewToken)) {
            if (ConvertStringSidToSidW(wszIntegritySid, &pIntegritySid)) {
                TIL.Label.Attributes = SE_GROUP_INTEGRITY;
                TIL.Label.Sid = pIntegritySid;

                // Set the process integrity level
                if (SetTokenInformation(hNewToken, TokenIntegrityLevel, &TIL,
                                        sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid))) {
                    POL.Policy = TOKEN_MANDATORY_POLICY_NO_WRITE_UP;
                    SetTokenInformation(hNewToken, TokenMandatoryPolicy, &POL, sizeof(TOKEN_MANDATORY_POLICY));
                    //printf("%i\n", GetLastError());
                }
                LocalFree(pIntegritySid);
            }
            CloseHandle(hNewToken);
        }
        CloseHandle(hToken);
    }
    return 0;
}
unsigned Process::SetPrivileges(const std::string& lpszPrivilege, bool bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hToken = NULL, hProcess = NULL;

    if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, PID_)) != NULL) {
        if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)) {

            if (!LookupPrivilegeValueA(NULL, lpszPrivilege.c_str(), &luid)) {
                if (hProcess) CloseHandle(hProcess);
                if (hToken) CloseHandle(hToken);

                throw std::runtime_error("Wrong privilege name.");
            }

            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;

            if (bEnablePrivilege)
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            else
                tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

            if (!AdjustTokenPrivileges(
                    hToken,
                    FALSE,      // If TRUE, function disables all privileges, if FALSE the function modifies privilege based on the tp
                    &tp,
                    sizeof(TOKEN_PRIVILEGES),
                    (PTOKEN_PRIVILEGES) NULL,
                    (PDWORD) NULL)) {
                if (hProcess) CloseHandle(hProcess);
                if (hToken) CloseHandle(hToken);

                throw std::runtime_error("Error setting privilege.");
            }

            if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
                if (hProcess) CloseHandle(hProcess);
                if (hToken) CloseHandle(hToken);

                throw std::runtime_error("Access denied.");
            }
        }
    }

    if (hProcess)
        CloseHandle(hProcess);
    if (hToken)
        CloseHandle(hToken);

    return 0;
}
