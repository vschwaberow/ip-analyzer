// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: src/cli_app.hh
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#pragma once

#include "ip_analyzer.hh"
#include <concepts>
#include <print>
#include <format>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <unistd.h>

namespace ip_analyzer {

template<typename T>
concept StringLike = std::convertible_to<T, std::string_view>;

constexpr std::string_view kAppName = "ip-analyzer";
constexpr std::string_view kVersion = "0.1.6";
constexpr std::string_view kAuthor = "Volker Schwaberow <volker@schwaberow.de>";

constexpr int kWidth = 80;

struct OutputColors {
    static constexpr std::string_view kReset = "\033[0m";
    static constexpr std::string_view kHeader = "\033[1;37m";
    static constexpr std::string_view kLabel = "\033[33m";
    static constexpr std::string_view kValue = "\033[32m";
    static constexpr std::string_view kBinary = "\033[35m";
    static constexpr std::string_view kPrompt = "\033[1;36m";
    static constexpr std::string_view kError = "\033[1;31m";
};

void PrintCopperBar(bool color_enabled);
void PrintHeader(const std::string &text, bool color_enabled);
void PrintRow(const std::string &label, const std::string &value, const std::string &binary,
              bool color_enabled);

class IPAnalyzerApp {
public:
    template<StringLike T, size_t Extent = std::dynamic_extent>
    int Run(std::span<T, Extent> args) {
        color_enabled_ = ::isatty(STDOUT_FILENO) != 0;
        for (size_t i = 1; i < args.size(); ++i) {
            std::string_view arg{args[i]};
            
            if (arg == "--version" || arg == "-v") {
                PrintVersion();
                return 0;
            } else if (arg == "--help" || arg == "-h") {
                PrintHelp();
                return 0;
            } else if (arg == "--interactive" || arg == "-i") {
                interactive_ = true;
            } else if (arg == "--json") {
                output_json_ = true;
            } else if (arg == "--compact") {
                compact_ = true;
            } else if (arg == "--no-color") {
                color_enabled_ = false;
            } else if (arg == "--stdin") {
                read_stdin_ = true;
            } else if (arg == "--ip") {
                if (i + 1 >= args.size()) {
                    PrintError("Missing value for --ip");
                    PrintHelp();
                    return 1;
                }
                input_ = std::string(args[++i]);
                has_input_ = true;
            } else if (arg.starts_with("--ip=")) {
                input_ = std::string(arg.substr(5));
                has_input_ = true;
            } else if (arg.starts_with("-")) {
                if (arg.starts_with("--list-tests") || 
                    arg.starts_with("--reporter") || 
                    arg.starts_with("--durations")) {
                    continue;
                }
                PrintError(std::format("Unknown option: {}", arg));
                PrintHelp();
                return 1;
            } else {
                input_ = arg;
                has_input_ = true;
            }
        }

        if (interactive_ && (read_stdin_ || has_input_)) {
            PrintError("Cannot combine --interactive with --stdin or direct IP input");
            PrintHelp();
            return 1;
        }

        if (read_stdin_ && has_input_) {
            PrintError("Cannot combine --stdin with a direct IP input");
            PrintHelp();
            return 1;
        }

        if (read_stdin_) {
            return RunFromStdin();
        }

        if (!has_input_) {
            if (interactive_) {
                PrintPrompt();
                if (!std::getline(std::cin, input_)) {
                    return 1;
                }
            } else {
                PrintHelp();
                return 0;
            }
        }

        try {
            IPAnalyzer analyzer(input_);
            if (output_json_) {
                PrintJsonResults(analyzer);
            } else {
                PrintResults(analyzer);
            }
        } catch (const std::exception &e) {
            PrintError(e.what());
            return 1;
        }

        return 0;
    }

private:
    std::string input_;
    bool has_input_ = false;
    bool interactive_ = false;
    bool output_json_ = false;
    bool compact_ = false;
    bool color_enabled_ = true;
    bool read_stdin_ = false;

    void PrintPrompt() const;
    void PrintVersion() const;
    void PrintHelp() const;
    void PrintResults(const IPAnalyzer &analyzer) const;
    void PrintJsonResults(const IPAnalyzer &analyzer) const;
    void PrintJsonObject(const IPAnalyzer &analyzer, const std::string &indent,
                         bool trailing_comma) const;
    int RunFromStdin();
    std::string GetIPv6Scope(const std::shared_ptr<IPAddress> &ip) const;
    void PrintError(const std::string &message) const;
};

}
