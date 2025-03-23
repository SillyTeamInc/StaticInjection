#pragma once
//
// Created by emi on 3/20/2025.
//
#include <LIEF/PE.hpp>
#include <LIEF/logging.hpp>

#define RVA_OFFSET(header) \
(header->VirtualAddress - header->PointerToRawData)

class util {
public:
    static void enable_virtual_terminal();
    static DWORD offset_from_rva(DWORD rva, PIMAGE_SECTION_HEADER header);
    static DWORD rva_from_offset(DWORD offset, PIMAGE_SECTION_HEADER header);

    static bool file_exists(const std::string &name);
    static void copy_to_clipboard(const std::string& string);
    static bool copy_file(const std::string& source, const std::string& destination);
    static bool is_file_locked(const std::string& filePath);

    static bool equals_ignore_case(const std::string& str1, const std::string& str2);
    static std::string trim_string(const std::string& string);
    static bool string_starts_with(const std::string& str, const std::string& prefix);
    static bool string_ends_with(const std::string& str, const std::string& suffix);
    static std::vector<std::string> split_string(const std::string& str, const std::string& delimiter);
    static std::pair<std::string, std::string> split_string_once(const std::string& str, const std::string& delimiter);

    static std::string get_executable_name();
};