#pragma once
//
// Created by emi on 3/22/2025.
//
#include "util.hpp"

struct argument {
    std::string name;
    std::string value;

    bool has_value() const {
        return !value.empty();
    }
};

struct default_arg {
    std::string name;
    std::string value;
    std::string description;
    bool required;
    bool is_flag;
    std::string extended_description;

    default_arg(const std::string& name, const std::string& value, const std::string& description, bool required = false, bool is_flag = false, const std::string& extended_description = "")
        : name(name), value(value), description(description), required(required), is_flag(is_flag), extended_description(extended_description) {}
};

struct parsed_arg_result {
    bool success;
    argument parsed_arg;
};


class arg_parser {
public:
    std::vector<argument> args;
    std::vector<default_arg> default_args;
    std::string program_description;

    arg_parser() = default;
    explicit arg_parser(const std::vector<default_arg>& default_args) : default_args(default_args) {}

    void add_arg(const std::string& name, const std::string& value);
    void add_default_arg(const std::string& name, const std::string& value, const std::string& description, bool required = false, bool is_flag = false, const std::string& extended_description = "");
    void set_description(const std::string& description);

    [[nodiscard]] bool has_flag(const std::string& name) const;
    [[nodiscard]] bool has_arg(const std::string& name) const;
    [[nodiscard]] std::string get_arg_value(const std::string& name) const;

    [[nodiscard]] bool parse_args(int argc, char* argv[]);
    [[nodiscard]] bool validate_args() const;
    [[nodiscard]] static parsed_arg_result parse_arg(const std::string& ppArg);

    void print_help() const;
};