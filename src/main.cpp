#include "util.hpp"
#include "psapi.h"
#include <windows.h>
#include <winnt.h>
#include <imagehlp.h>

#include "arg_parser.hpp"

uint32_t get_import_address_offset(const std::vector<uint8_t>& buffer, const std::string& moduleName, const std::string& functionName) {
    const auto binary= LIEF::PE::Parser::parse(buffer);
    const auto imports = binary->imports();

    std::reverse(imports.begin(), imports.end());

    for (const auto& import : imports) {
        uint32_t iatRVA = import.import_address_table_rva();
        if (import.name() == moduleName) {
            int functionIndex = 0;
            for (const auto& entry : import.entries()) {
                if (entry.name() == functionName) {
                    return iatRVA + (functionIndex * 8);
                }
                ++functionIndex;
            }
        }
    }
    return 0;
}

int main(int argc, char* argv[])
{
    util::enable_virtual_terminal();

    LIEF::PE::Builder::config_t builderConfig;
    builderConfig.imports = true;
    builderConfig.relocations = true;


    auto console = spdlog::stdout_color_mt("console");
    console->set_pattern("\033[90m[\033[33m%T\033[90m] %^[%l]%$\033[0m %v");
    spdlog::set_default_logger(console);
    spdlog::set_level(spdlog::level::trace);
    LIEF::logging::set_level(LIEF::logging::LEVEL::INFO);

    arg_parser parser;
    std::string description = "A program to mess with the import table of a PE file.\n"
                           "Can be used to make a program load a DLL at runtime.\n";
    parser.set_description(description);
    parser.add_default_arg("help", "",  "Show help message", false, true);
    parser.add_default_arg("target", "example app.exe", "Path to the target .exe file", true);
    parser.add_default_arg("action", "add", "Action to perform (add, remove, list)", true);
    std::string symbolDescription = "The DLL and function to add/remove from the target's imports\n"
        "Format: DLL_PATH::FUNCTION_NAME\n"
        "The DLL must be present in a directory that can be found by Windows when loading the target.";
    parser.add_default_arg("symbol", "example lib.dll::exampleFunction", "The dll and function to add/remove from the target's imports", false, false, symbolDescription);
    parser.add_default_arg("save", "example app_infected.exe", "Path to save the modified file", false, false, "Defaults to the target file with \"_modified\" appended to the name");
    parser.add_default_arg("force", "", "Attempts to force an operation", false, true, "Use with caution! This may cause unexpected behavior.");

    if (!parser.parse_args(argc, argv))
    {
        spdlog::critical("Your arguments couldn't be parsed! Please check your arguments and try again.");
        parser.print_help();
        return 1;
    }

    if (parser.has_flag("help"))
    {
        parser.print_help();
        return 0;
    }

    if (!parser.validate_args())
    {
        parser.print_help();
        return 1;
    }

    std::string action = parser.get_arg_value("action");

    if (action != "add" && action != "remove" && action != "list")
    {
        spdlog::critical("Invalid action specified! Use 'add', 'remove', or 'list'.");
        return 1;
    }

    std::string target = parser.get_arg_value("target");
    if (!util::file_exists(target))
    {
        spdlog::critical("The target file you specified does not exist!");
        return 1;
    }

    if (util::is_file_locked(target))
    {
        spdlog::critical("The target file is locked! Please close any applications that may be using it.");
        return 1;
    }

    HANDLE hFile = CreateFileA(target.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        spdlog::critical("Failed to open the target file!");
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE)
    {
        CloseHandle(hFile);
        spdlog::critical("Failed to get file size!");
        return 1;
    }

    std::string targetFilename = std::filesystem::path(target).filename().string();

    bool signedTarget = util::has_code_signature(target);
    if (signedTarget)
    {
        spdlog::warn("THE TARGET FILE IS SIGNED!");
        spdlog::warn("Modifying a signed file may cause the signature to be invalidated.");
        spdlog::warn("We are NOT responsible for any issues that may arise from this.");
        spdlog::warn("\033[31mTHIS MAY MAKE THE FILE UNSIGNED OR FAIL TO LOAD.\033[0m");
    }

    std::vector<uint8_t> buffer(fileSize);
    DWORD bytesRead = 0;

    if (!signedTarget)
    {
        util::clear_current_console_line();
        util::write("Reading target file: " + targetFilename + "\r");
    }

    ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    if (bytesRead != fileSize)
    {
        spdlog::critical("Failed to read the entire file!");
        return 1;
    }

    if (!signedTarget)
    {
        util::clear_current_console_line();
        util::write("Parsing target file: " + targetFilename + "\r");
    }

    auto binary = LIEF::PE::Parser::parse(buffer);
    if (!signedTarget) util::clear_current_console_line();

    auto imports = binary->imports();

    if (action == "list")
    {
        spdlog::info("Imported functions:");
        for (const auto& import : imports)
        {
            int i = 0;
            for (const auto& entry : import.entries())
            {
                if (!entry.is_ordinal())
                {
                    //spdlog::info("  Function: {} ({:X})", entry.name(), entry.iat_value());
                    spdlog::info("  Import - {}::{} ({:X})", import.name(), entry.name(), (import.import_address_table_rva() + (i * 8)));
                }
                i += 1;
            }
        }
        spdlog::info(" The hex value after the import name is the RVA (Relative Virtual Address) of the import in the IAT (Import Address Table)");

        spdlog::info("Exported functions:");
        for (const auto& exportEntry : binary->exported_functions())
        {
            spdlog::info("  Export - {}::{} ({:X})", targetFilename, exportEntry.name(), exportEntry.address());
        }
        if (binary->exported_functions().empty())
        {
            spdlog::info("  No exported functions found!");
        }

        return 0;
    }

    if (!parser.has_arg("symbol"))
    {
        spdlog::error("No symbol specified! Use --symbol:DLL_PATH::FUNCTION_NAME to specify the DLL and function!!");
        return 1;
    }

    if (!parser.has_arg("save")) {
        std::string saveFileName = std::filesystem::path(target).filename().string();
        std::string extension = saveFileName.substr(saveFileName.find_last_of("."));
        saveFileName = saveFileName.substr(0, saveFileName.find_last_of("."));

        std::string saveFileDir = std::filesystem::path(target).parent_path().string();
        if (!saveFileDir.empty() && saveFileDir.back() != '\\')
        {
            saveFileDir += "\\";
        }
        std::string saveFilePath = saveFileDir + saveFileName + "_modified" + extension;
        parser.add_arg("save", saveFilePath);
        spdlog::warn("No save path specified! Defaulting to: {}", saveFilePath);
    } else {
        std::string saveFileName = std::filesystem::path(parser.get_arg_value("save")).filename().string();
        std::string saveFileDir = std::filesystem::path(parser.get_arg_value("save")).parent_path().string();
        if (!util::file_exists(saveFileDir))
        {
            spdlog::error("The specified save directory does not exist!");
            return 1;
        }
        spdlog::info("Saving to: {}", parser.get_arg_value("save"));
    }

    std::string saveTarget = parser.get_arg_value("save");
    std::string dllToLoad = parser.get_arg_value("symbol");
    auto dllAndFunction = util::split_string_once(dllToLoad, "::");
    std::string dllPath = dllAndFunction.first;
    std::string functionName = dllAndFunction.second;

    if (dllPath.empty() || functionName.empty())
    {
        spdlog::error("Invalid DLL and function format! Use 'DLL_PATH::FUNCTION_NAME'.");
        return 1;
    }

    if (action == "remove")
    {
        // existing check isn't required for remove
        // bc we aren't really using the dll itself
        if (!parser.has_flag("force"))
        {
            spdlog::warn("WARNING: The remove action will likely not work correctly.");
            spdlog::warn("I highly recommend to just restore the original file.");
            spdlog::warn("\033[31mIf you're absolutely sure you want to continue, append the --force flag to your args and run this again.\033[0m");
            return 1;
        }
        spdlog::info("Attempting to remove import: {}::{}", dllPath, functionName);

        bool found = false;
        for (auto& import : imports)
        {
            if (import.name() == dllPath)
            {
                spdlog::debug("Matching DLL found!");
                auto entries = import.entries();
                if (entries.empty())
                {
                    spdlog::critical("No entries found for DLL: {}", dllPath);
                    found = false;
                    break;
                }

                for (auto& entry : entries)
                {
                    if (entry.name() == functionName)
                    {
                        spdlog::debug("Matching function found!");
                        found = true;
                        break;
                    }
                }

                if (found)
                {
                    spdlog::info("Removing import: {}::{}", dllPath, functionName);
                    import.remove_entry(functionName);
                    spdlog::info("Import removed successfully!");
                    break;
                }
            }
        }

        if (!found)
        {
            spdlog::error("Failed to remove import: {}::{}", dllPath, functionName);
            return 1;
        }

        if (util::is_file_locked(saveTarget))
        {
            spdlog::error("The file to save to is locked! Please close any applications that may be using it.");
            spdlog::critical("Failed to save the modified file.");
            return 1;
        }

        std::ofstream output(saveTarget, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
        if (!output.is_open())
        {
            spdlog::critical("Failed to open output file!");
            return 1;
        }
        binary->write(output, builderConfig);
        output.close();
        spdlog::info("Modified binary saved to: {}", saveTarget);
        return 0;
    }

    if (action == "add")
    {
        spdlog::info("Attempting to add import: {}::{}", dllPath, functionName);

        std::string moduleName = std::filesystem::path(dllPath).filename().string();

        for (const auto& import : imports)
        {
            if (import.name() == moduleName)
            {
                for (const auto& entry : import.entries())
                {
                    if (entry.name() == functionName)
                    {
                        spdlog::error("Import already exists: {}::{}", moduleName, functionName);
                        return 1;
                    }
                }
            }
        }

        if (!parser.has_arg("force"))
        {
            if (!util::file_exists(dllPath))
            {
                spdlog::error("The specified DLL does not exist!");
                return 1;
            }
            auto dllBinary = LIEF::PE::Parser::parse(dllPath);
            if (!dllBinary)
            {
                spdlog::error("Failed to parse the DLL file!");
                return 1;
            }
            auto dllExports = dllBinary->exported_functions();

            bool found = false;
            for (const auto& exportEntry : dllExports)
            {
                if (exportEntry.name() == functionName)
                {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                spdlog::error("The specified function does not exist in the DLL!");
                spdlog::info("TIP: You can also list exports for this DLL by typing --action:list --target:" + dllPath.contains(" ") ? "\"" + dllPath + "\"" : dllPath);
                spdlog::warn("If you are sure the function exists, append --force to override this check.");
                return 1;
            }
        }

        std::string dllDirectory = std::filesystem::path(dllPath).parent_path().string();
        std::string prgDir = std::filesystem::path(target).parent_path().string();
        if (dllDirectory != prgDir)
        {
            spdlog::warn("The DLL is not in the same directory as the target file!");
            spdlog::warn("If the program fails to launch, you MUST copy the DLL to the same directory as the target file!");
        }

        if (binary->has_import(moduleName))
        {
            spdlog::warn("Library already exists, using existing module");
            auto lib = binary->get_import(moduleName);
            lib->add_entry(LIEF::PE::ImportEntry(functionName));
            spdlog::info("Import added successfully!");
        } else
        {
            spdlog::info("Adding new import: {}::{}", moduleName, functionName);
            auto& lib = binary->add_import(moduleName);
            lib.add_entry(LIEF::PE::ImportEntry(functionName));
            spdlog::info("Import added successfully!");
        }

        std::ofstream output(saveTarget, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
        if (!output.is_open())
        {
            spdlog::critical("Failed to open output file!");
            return 1;
        }
        binary->write(output, builderConfig);
        output.close();
        spdlog::info("Modified binary saved to: {}", saveTarget);
    }


    return 0;
}
