//
// Created by emi on 3/20/2025.
//

#include "util.hpp"

void util::enable_virtual_terminal()  {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

DWORD util::offset_from_rva(DWORD rva, PIMAGE_SECTION_HEADER header)
{
    return rva + RVA_OFFSET(header);
}

DWORD util::rva_from_offset(DWORD offset, PIMAGE_SECTION_HEADER header)
{
    return offset - RVA_OFFSET(header);
}

void util::copy_to_clipboard(const std::string& string)
{
    if (OpenClipboard(nullptr))
    {
        EmptyClipboard();
        HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, string.size() + 1);
        memcpy(GlobalLock(hGlob), string.c_str(), string.size() + 1);
        GlobalUnlock(hGlob);
        SetClipboardData(CF_TEXT, hGlob);
        CloseClipboard();
    }
    else
    {
        spdlog::error("Failed to open clipboard");
    }
}

bool util::file_exists(const std::string &name) {
    return std::filesystem::exists(name);
}

bool util::copy_file(const std::string& source, const std::string& destination)
{
    try
    {
        std::filesystem::copy(source, destination, std::filesystem::copy_options::overwrite_existing);
        return true;
    }
    catch (const std::filesystem::filesystem_error& e)
    {
        spdlog::error("Error copying file: {}", e.what());
        return false;
    }
}

bool util::is_file_locked(const std::string& filePath)
{
    std::ifstream file(filePath);
    std::ofstream output(filePath, std::ios::app);
    bool isLocked = !file.is_open() || !output.is_open();
    if (file.is_open()) file.close();
    if (output.is_open()) output.close();
    return isLocked;
}

bool util::equals_ignore_case(const std::string& str1, const std::string& str2)
{
    return std::ranges::equal(str1, str2,
                              [](const char a, const char b) { return tolower(a) == tolower(b); });
}

std::string util::trim_string(const std::string& string)
{
    std::string trimmed = string;
    trimmed.erase(trimmed.begin(), std::ranges::find_if(trimmed, [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    trimmed.erase(std::find_if(trimmed.rbegin(), trimmed.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), trimmed.end());
    return trimmed;
}

bool util::string_starts_with(const std::string& str, const std::string& prefix)
{
    return str.rfind(prefix, 0) == 0;
}

bool util::string_ends_with(const std::string& str, const std::string& suffix)
{
    if (str.length() < suffix.length()) {
        return false;
    }
    return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}

std::vector<std::string> util::split_string(const std::string& str, const std::string& delimiter)
{
    std::vector<std::string> tokens;
    size_t start = 0;
    size_t end = str.find(delimiter);
    while (end != std::string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
        end = str.find(delimiter, start);
    }
    tokens.push_back(str.substr(start, end));
    return tokens;
}

std::pair<std::string, std::string> util::split_string_once(const std::string& str, const std::string& delimiter)
{
    size_t pos = str.find(delimiter);
    if (pos == std::string::npos) {
        return { str, "" };
    }
    return { str.substr(0, pos), str.substr(pos + delimiter.length()) };
}

std::string util::get_executable_name()
{
    char buffer[MAX_PATH];
    GetModuleFileNameA(nullptr, buffer, MAX_PATH);
    std::string fullPath(buffer);
    return std::filesystem::path(fullPath).filename().string();
}
