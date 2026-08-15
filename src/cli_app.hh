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
#include <ranges>
#include <cstdio>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace ip_analyzer {

template<typename T>
concept StringLike = std::convertible_to<T, std::string_view>;

constexpr std::string_view kAppName = "ip-analyzer";
constexpr std::string_view kVersion = "0.1.9";
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
#ifdef _WIN32
        color_enabled_ = _isatty(_fileno(stdout)) != 0;
#else
        color_enabled_ = ::isatty(STDOUT_FILENO) != 0;
#endif
        enum class PendingValue { None, Ip, Contains, Overlaps, Range };
        PendingValue pending = PendingValue::None;

        for (std::string_view arg : args | std::views::drop(1)) {
            if (pending != PendingValue::None && !arg.starts_with('-')) {
                switch (pending) {
                case PendingValue::Ip:
                    input_ = std::string(arg);
                    has_input_ = true;
                    break;
                case PendingValue::Contains:
                    contains_target_ = std::string(arg);
                    has_contains_ = true;
                    break;
                case PendingValue::Overlaps:
                    overlaps_target_ = std::string(arg);
                    has_overlaps_ = true;
                    break;
                case PendingValue::Range:
                    range_input_ = std::string(arg);
                    has_range_ = true;
                    break;
                case PendingValue::None:
                    break;
                }
                pending = PendingValue::None;
                continue;
            }

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
            } else if (arg == "--list-ips") {
                list_ips_ = true;
            } else if (arg == "--ip") {
                pending = PendingValue::Ip;
            } else if (arg.starts_with("--ip=")) {
                input_ = std::string(arg.substr(5));
                has_input_ = true;
            } else if (arg == "--contains") {
                pending = PendingValue::Contains;
            } else if (arg.starts_with("--contains=")) {
                contains_target_ = std::string(arg.substr(11));
                has_contains_ = true;
            } else if (arg == "--overlaps") {
                pending = PendingValue::Overlaps;
            } else if (arg.starts_with("--overlaps=")) {
                overlaps_target_ = std::string(arg.substr(11));
                has_overlaps_ = true;
            } else if (arg == "--range") {
                pending = PendingValue::Range;
            } else if (arg.starts_with("--range=")) {
                range_input_ = std::string(arg.substr(8));
                has_range_ = true;
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

        if (pending == PendingValue::Ip) {
            PrintError("Missing value for --ip");
            PrintHelp();
            return 1;
        }
        if (pending == PendingValue::Contains) {
            PrintError("Missing value for --contains");
            PrintHelp();
            return 1;
        }
        if (pending == PendingValue::Overlaps) {
            PrintError("Missing value for --overlaps");
            PrintHelp();
            return 1;
        }
        if (pending == PendingValue::Range) {
            PrintError("Missing value for --range");
            PrintHelp();
            return 1;
        }

        if (has_contains_ && has_overlaps_) {
            PrintError("Cannot combine --contains and --overlaps");
            PrintHelp();
            return 1;
        }
        if ((has_contains_ || has_overlaps_) && (list_ips_ || has_range_)) {
            PrintError("Cannot combine --contains or --overlaps with --list-ips or --range");
            PrintHelp();
            return 1;
        }

        if (has_range_) {
            input_ = range_input_;
            has_input_ = true;
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

        if (read_stdin_ && has_range_) {
            PrintError("Cannot combine --stdin with --range");
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
            } else if (has_contains_ || has_overlaps_ || list_ips_) {
                PrintError("Missing IP/CIDR subject");
                PrintHelp();
                return 1;
            } else {
                PrintHelp();
                return 0;
            }
        }

        try {
            if (const auto range = IPAnalyzer::parse_address_range(input_)) {
                if (has_contains_ || has_overlaps_) {
                    PrintError("Cannot combine an address range with --contains or --overlaps");
                    PrintHelp();
                    return 1;
                }
                if (list_ips_) {
                    return RunListIpsRange(range->first, range->second);
                }
                return RunRangeToCidr(range->first, range->second);
            }
            if (has_range_) {
                PrintError("Invalid address range");
                PrintHelp();
                return 1;
            }

            IPAnalyzer analyzer(input_);
            if (has_contains_) {
                return RunContains(analyzer, contains_target_);
            }
            if (has_overlaps_) {
                return RunOverlaps(analyzer, overlaps_target_);
            }
            if (list_ips_) {
                return RunListIps(analyzer);
            }
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
    std::string contains_target_;
    std::string overlaps_target_;
    std::string range_input_;
    bool has_input_ = false;
    bool has_contains_ = false;
    bool has_overlaps_ = false;
    bool has_range_ = false;
    bool list_ips_ = false;
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
    int RunContains(const IPAnalyzer &subject, std::string_view candidate);
    int RunOverlaps(const IPAnalyzer &subject, std::string_view other);
    int RunListIps(const IPAnalyzer &subject);
    int RunListIpsRange(std::string_view first, std::string_view last);
    int RunRangeToCidr(std::string_view first, std::string_view last);
    void PrintIpListJson(std::string_view network_or_first, std::string_view last,
                         const std::vector<std::string> &hosts, bool is_range) const;
    void PrintRelation(std::string_view operation, std::string_view subject,
                       std::string_view other, std::string_view other_label,
                       bool result) const;
    std::string GetIPv6Scope(const std::shared_ptr<IPAddress> &ip) const;
    void PrintError(const std::string &message) const;
};

}
