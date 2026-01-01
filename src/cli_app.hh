// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: src/cli_app.hh
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#pragma once

#include "ip_analyzer.hh"
#include <fmt/color.h>
#include <fmt/core.h>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <span>

namespace ip_analyzer {

constexpr std::string_view kAppName = "ip-analyzer";
constexpr std::string_view kVersion = "0.1.5";
constexpr std::string_view kAuthor = "Volker Schwaberow <volker@schwaberow.de>";

constexpr int kWidth = 80;

struct OutputColors {
    static constexpr auto kHeader = fmt::emphasis::bold | fg(fmt::color::white);
    static constexpr auto kLabel = fg(fmt::color::yellow);
    static constexpr auto kValue = fg(fmt::color::green);
    static constexpr auto kBinary = fg(fmt::color::magenta);
    static constexpr auto kPrompt = fg(fmt::color::cyan) | fmt::emphasis::bold;
    static constexpr auto kError = fg(fmt::color::red) | fmt::emphasis::bold;
};

void PrintCopperBar();
void PrintHeader(const std::string &text);
void PrintRow(const std::string &label, const std::string &value, const std::string &binary = "");

class IPAnalyzerApp {
public:
    template<typename CharT>
    int Run(std::span<CharT*> args) {
        for (size_t i = 1; i < args.size(); ++i) {
            std::string_view arg{args[i]};
            
            if (arg == "--version" || arg == "-v") {
                PrintVersion();
                return 0;
            } else if (arg == "--help" || arg == "-h") {
                PrintHelp();
                return 0;
            } else if (arg.starts_with("-")) {
                if (arg.starts_with("--list-tests") || 
                    arg.starts_with("--reporter") || 
                    arg.starts_with("--durations")) {
                    continue;
                }
                fmt::print(OutputColors::kError, "Unknown option: {}\n", arg);
                PrintHelp();
                return 1;
            } else {
                input_ = arg;
                has_input_ = true;
            }
        }

        if (!has_input_) {
            PrintPrompt();
            if (!std::getline(std::cin, input_)) {
                return 1;
            }
        }

        try {
            IPAnalyzer analyzer(input_);
            PrintResults(analyzer);
        } catch (const std::exception &e) {
            PrintError(e.what());
            return 1;
        }

        return 0;
    }

private:
    std::string input_;
    bool has_input_ = false;

    void PrintPrompt() const;
    void PrintVersion() const;
    void PrintHelp() const;
    void PrintResults(const IPAnalyzer &analyzer) const;
    std::string GetIPv6Scope(const std::shared_ptr<IPAddress> &ip) const;
    void PrintError(const std::string &message) const;
};

}
