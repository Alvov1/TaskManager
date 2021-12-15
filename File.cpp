#include "File.h"

File::File(const std::filesystem::path& path) : filePath(path), Name_(path.string()){
    Name_ = Name_.substr(Name_.find_last_of('\\') + 1);
    GetFileOwner(path.string());
    GetFileAcl(path.string());
    GetFileIntegrity(path.string());
}
void File::GetFileOwner(const std::string &filename) {
    ownerName.clear();
    auto lpSid = (LPSTR) "Unknown";
    PSID psid = nullptr;
    PSECURITY_DESCRIPTOR pDescr;

    if (!GetNamedSecurityInfoA(filename.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &psid, nullptr, nullptr, nullptr, &pDescr)){
        SID_NAME_USE snu;
        char name[512] = { 0 };
        char domain[512] = { 0 };
        DWORD nameLen = 512;
        DWORD domainLen = 512;

        if (LookupAccountSidA(nullptr, psid, name, &nameLen, domain, &domainLen, &snu)){
            ConvertSidToStringSidA(psid, &lpSid);
            ownerName = std::string("Owner name: ") + name + ".\nDomain: " + domain + ".\nSid: " + lpSid + ".";
        }
    } else
        throw std::runtime_error("Error in getting file owner name. GetSecurityInfo error = " + std::to_string(GetLastError()));

    if (pDescr)
        LocalFree(pDescr);
    if (lpSid)
        LocalFree(lpSid);
}
void File::GetFileIntegrity(const std::string &filename) {
    DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    PACL Sacl = nullptr;

    if (!GetNamedSecurityInfoA(filename.c_str(), SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, &Sacl, &pSD)) {
        if (Sacl != nullptr && 0 < Sacl->AceCount) {
            SYSTEM_MANDATORY_LABEL_ACE* ace = nullptr;
            if (GetAce(Sacl, 0, reinterpret_cast<void**>(&ace)))
                integrityLevel = reinterpret_cast<SID*>(&ace->SidStart)->SubAuthority[0];
        }


        LPSTR stringSD;
        ULONG stringSDLen = 0;

        ConvertSecurityDescriptorToStringSecurityDescriptorA(pSD, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, &stringSD, &stringSDLen);

        switch(integrityLevel) {
            case(0x1000):
                integrity_ = Low;
                break;
            case(0x2000):
                integrity_ = Medium;
                break;
            case(0x3000):
                integrity_ = High;
                break;
            default:
                integrity_ = Undefined;
                break;
        }

        if (pSD)
            LocalFree(pSD);
    } else
        throw std::runtime_error("Access denied. Error in getting file integrity: " + std::to_string(GetLastError()));
}
void File::GetFileAcl(const std::string &filename) {
    ACL.clear();
    auto lpSid = (LPSTR) "UNKNOWN_SID";
    PACL pl = nullptr;
    PSECURITY_DESCRIPTOR pDescr;
    ACL_SIZE_INFORMATION aclSize;
    LPVOID aceInfo;

    ACL.clear();

    if (!GetNamedSecurityInfoA(filename.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pl, nullptr, &pDescr)){
        GetAclInformation(pl, &aclSize, sizeof(aclSize), AclSizeInformation);

        for (DWORD i = 0; i < aclSize.AceCount; i++){
            PSID psid = nullptr;
            ACCESS_ALLOWED_ACE* accAllowedAce;
            SID_NAME_USE snu;
            char name[512] = { 0 };
            char domain[512] = { 0 };
            DWORD nameLen = 512;
            DWORD domainLen = 512;

            GetAce(pl, i, &aceInfo);
            accAllowedAce = (ACCESS_ALLOWED_ACE*) aceInfo;
            psid = (PSID) & (accAllowedAce->SidStart);

            if (LookupAccountSidA(nullptr, psid, name, &nameLen, domain, &domainLen, &snu)){
                ACCESS_MASK Mask = accAllowedAce->Mask;
                if (accAllowedAce->Header.AceType == ACCESS_DENIED_ACE_TYPE)
                    ACL += "Denied for:\n";
                if (accAllowedAce->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
                    ACL += "Allowed for:\n";

                ConvertSidToStringSidA(psid, &lpSid);
//                std::cout << domain << "\\" << name << " " << lpSid << std::endl;
                LocalFree(lpSid);

                if (Mask & FILE_ALL_ACCESS)
                    ACL += "\tFull acces\n";

                if (Mask & FILE_READ_ATTRIBUTES)
                    ACL += "\tRead attribute\n";

                if (Mask & FILE_READ_DATA)
                    ACL += "\tRead dat\n";

                if (Mask & FILE_APPEND_DATA)
                    ACL += "\tAppend dat\n";

                if (Mask & FILE_WRITE_ATTRIBUTES)
                    ACL += "\tWrite attribute\n";

                if (Mask & FILE_WRITE_EA)
                    ACL += "\tWrite extended attribute\n";

                if (Mask & FILE_EXECUTE)
                    ACL += "\tExecute fil\n";

//                std::cout << std::endl;
            }
        }
    }
//    else
//        std::cout << "Error in getting file ACL for " << Name_ << ". GetNamedSecurityInfo error = " << GetLastError() << std::endl;
}

std::wstring File::About() const {
    std::string result = "Filename: " + Name_ + "\n" + ownerName + "\nACL:\n" + ACL + "\nIntegrity: ";

    switch(integrity_) {
        case Low:
            result += "Low\n";
            break;
        case Medium:
            result += "Medium\n";
            break;
        case High:
            result += "High\n";
            break;
        default:
            result += "Unknown\n";
            break;
    }

    return {result.begin(), result.end()};
}

unsigned File::SetOwner(const std::string& newOwner){
    PSID pSid = nullptr;
    ConvertStringSidToSidA(newOwner.c_str(), &pSid);
    if (!pSid)
        throw std::runtime_error("Error in converting string SID to pSID");

    SECURITY_INFORMATION SecInfo = OWNER_SECURITY_INFORMATION;

    if (SetNamedSecurityInfoA((LPSTR) filePath.string().c_str(), SE_FILE_OBJECT, SecInfo, pSid, nullptr, nullptr, nullptr))
        throw std::runtime_error("SetNamedSecurityInfo error " + std::to_string(GetLastError()));

    if (pSid)
        LocalFree(pSid);
    return 0;
}
unsigned File::SetACL(const std::string& spermissions, ACCESS_MODE mode) {
    //https://docs.microsoft.com/en-us/windows/win32/secauthz/modifying-the-acls-of-an-object-in-c--

    PSID pEveryoneSID = nullptr;
    PACL pACL = nullptr;
    EXPLICIT_ACCESS ea[1];
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    DWORD permissions = 0;

    for(auto &i : spermissions)
        switch(i) {
            case 'r':
                permissions |= FILE_READ_DATA | FILE_READ_ATTRIBUTES;
                break;
            case 'w':
                permissions |= FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA;
                break;
            case 'x':
                permissions |= FILE_READ_DATA | FILE_EXECUTE;
                break;
            default:
                throw std::runtime_error("Incorrect arguments");
        }

    AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0,
        0, 0, 0, 0, 0, 0, &pEveryoneSID);

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    ZeroMemory(&ea, 1 * sizeof(EXPLICIT_ACCESS));
    ea[0].grfAccessPermissions = permissions;
    ea[0].grfAccessMode = mode;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

    // Create a new ACL that contains the new ACEs.
    SetEntriesInAcl(1, ea, nullptr, &pACL);

    // Initialize a security descriptor.
    auto pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);

    InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);

    // Add the ACL to the security descriptor.
    SetSecurityDescriptorDacl(pSD, true, pACL, false);

    //Change the security attributes
    SetFileSecurityA(filePath.string().c_str(), DACL_SECURITY_INFORMATION, pSD);

    if (pEveryoneSID)
        FreeSid(pEveryoneSID);
    if (pACL)
        LocalFree(pACL);
    if (pSD)
        LocalFree(pSD);

    return 0;
}
unsigned File::SetIntegrity(integrity newInt) {
    #define LOW_INTEGRITY_SDDL_SACL_W L"S:AI(ML;;NW;;;LW)"
    #define MEDIUM_INTEGRITY_SDDL_SACL_W L"S:AI(ML;;NW;;;ME)"
    #define HIGH_INTEGRITY_SDDL_SACL_W L"S:AI(ML;;NW;;;HI)"

    DWORD dwErr = ERROR_SUCCESS;
    PSECURITY_DESCRIPTOR pSD = nullptr;

    PACL pSacl = nullptr;
    BOOL fSaclPresent = FALSE;
    BOOL fSaclDefaulted = FALSE;
    LPCWSTR sddl;

    switch(newInt) {
        case Low:
            sddl = LOW_INTEGRITY_SDDL_SACL_W;
            break;
        case Medium:
            sddl = MEDIUM_INTEGRITY_SDDL_SACL_W;
            break;
        case High:
            sddl = HIGH_INTEGRITY_SDDL_SACL_W;
            break;
        default:
            throw std::runtime_error("Unknown integrity level");
    }

    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, nullptr) &&
    GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted) &&
            SetNamedSecurityInfoA((LPSTR) filePath.string().c_str(),
    SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, pSacl))
                throw std::runtime_error("Error in setting integrity level. SetNamedSecurityInfo error " + std::to_string(GetLastError()));

    LocalFree(pSD);
    return 0;
}
