//
// Created by emi on 3/22/2025.
//

// powered by masochism™️
#include "arg_parser.hpp"

void arg_parser::add_arg(const std::string& name, const std::string& value)
{
    args.push_back({name, value});
}

void arg_parser::add_default_arg(const std::string& name, const std::string& value, const std::string& description, bool required, bool is_flag, const std::string& extended_description)
{
    default_args.push_back({name, value, description, required, is_flag, extended_description});
}
// i don't understand c++ sometimes
void arg_parser::set_description(const std::string& description)
{
    program_description = description;
}

bool arg_parser::has_flag(const std::string& name) const
{
    return std::ranges::find_if(args, [&name](const argument& arg) { return arg.name == name && !arg.has_value(); }) != args.end();
}

bool arg_parser::has_arg(const std::string& name) const
{
    return std::ranges::find_if(args, [&name](const argument& arg) { return arg.name == name && arg.has_value();; }) != args.end();
}

std::string arg_parser::get_arg_value(const std::string& name) const
{
    auto it = std::ranges::find_if(args, [&name](const argument& arg) { return arg.name == name; });
    if (it != args.end()) {
        return it->value;
    }
    return "";
}

bool arg_parser::parse_args(const int argc, char* argv[])
{
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto parsed_result = parse_arg(arg);
        if (parsed_result.success) {
            args.push_back(parsed_result.parsed_arg);
        } else {
            spdlog::error("Failed to parse argument #{}: {}", i, arg);
            return false;
        }
    }
    return true;
}

bool arg_parser::validate_args() const
{
    if (args.empty()) {
        spdlog::error(":: No arguments provided!");
        return false;
    }

    for (const auto& arg : args) {
        auto it = std::ranges::find_if(default_args, [&arg](const default_arg& def_arg) {
            return def_arg.name == arg.name;
        });

        if (it == default_args.end()) {
            spdlog::error(":: Unknown argument \"{}\"!", arg.name);
            return false;
        }

        if (!it->is_flag && !arg.has_value()) {
            spdlog::error(":: Argument \"{}\" requires a value!", arg.name);
            return false;
        }

        if (it->is_flag && arg.has_value()) {
            spdlog::error(":: Argument \"{}\" does not accept a value!", arg.name);
            return false;
        }
    }

    for (const auto& arg : default_args) {
        if (arg.required) {
            auto it = std::ranges::find_if(args, [&arg](const argument& a) {
                return a.name == arg.name;
            });

            if (it == args.end()) {
                spdlog::error(":: Required argument \"{}\" is missing!", arg.name);
                return false;
            }
        }
    }
    return true;
}

parsed_arg_result arg_parser::parse_arg(const std::string& ppArg)
{
    parsed_arg_result result;
    result.success = false;
    std::string arg = util::trim_string(ppArg);

    if (arg.empty() || !util::string_starts_with(arg, "--")) {
        spdlog::error("Invalid argument format: {}", arg);
        return result;
    }

    arg = util::trim_string(arg.substr(2));

    std::pair<std::string, std::string> split_result = util::split_string_once(arg, ":");
    std::string name = split_result.first;
    std::string value = split_result.second;
    if (name.empty()) {
        return result;
    }

    result.success = true;
    result.parsed_arg.name = name;
    result.parsed_arg.value = value;
    return result;
}

void arg_parser::print_help() const
{
    spdlog::info("");
    spdlog::info("Usage: {} [options]", util::get_executable_name());
    std::vector<std::string> lines = util::split_string(program_description, "\n");
    for (const auto& line : lines) {
        spdlog::info("{}", line);
    }
    spdlog::info("Options:");
    for (const auto& arg : default_args) {
        spdlog::info("  --{}{} - {}", arg.name, arg.required ? " (required)" : "", arg.description);
        if (!arg.is_flag) spdlog::info("    ex: --{}:{}",  arg.name, arg.value.contains(" ") ? "\"" + arg.value + "\"" : arg.value);
        if (!arg.extended_description.empty())
        {
            for (const auto& line : util::split_string(arg.extended_description, "\n")) {
                spdlog::info("    {}", line);
            }
        }

        spdlog::info("");
    }

}
