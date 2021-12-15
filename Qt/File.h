#ifndef PROJECT_FILE_H
#define PROJECT_FILE_H

#include <iostream>
#include <fstream>
#include <list>
#include <string>
#include <filesystem>
#include <vector>

#include <windows.h>
#include <clocale>
#include <tlhelp32.h>
#include <sddl.h>
#include <aclapi.h>
#include <psapi.h>

#include "Integrity.h"

class File {
    std::filesystem::path filePath = std::filesystem::current_path();
    std::string Name_ = "Undefined";
    std::string ownerName = "Undefined";
    std::string ACL = "Undefined";
    integrity integrity_ = Low;

    void GetFileOwner(const std::string& filename);
    void GetFileAcl(const std::string& filename);
    void GetFileIntegrity(const std::string& filename);

public:
    explicit File(const std::filesystem::path& path);

    std::wstring About() const;
    std::string Name() const { return Name_; }

    unsigned SetOwner(const std::string& newOwner);
    unsigned SetACL(const std::string& permisssions, ACCESS_MODE mode);
    unsigned SetIntegrity(integrity newInt);
};

#endif //PROJECT_FILE_H
