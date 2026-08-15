// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: src/cli_app.hh
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#pragma once

#include "ip_analyzer.hh"
#include <bit>
#include <charconv>
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
        enum class PendingValue {
            None, Ip, Contains, Overlaps, Range, Relate, Adjacent, Exclude,
            Intersect, Split, Nth
        };
        PendingValue pending = PendingValue::None;

        for (std::string_view arg : args | std::views::drop(1)) {
            if (pending == PendingValue::Nth && ParseNth(arg)) {
                has_nth_ = true;
                pending = PendingValue::None;
                continue;
            }

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
                case PendingValue::Relate:
                    relate_target_ = std::string(arg);
                    has_relate_ = true;
                    break;
                case PendingValue::Adjacent:
                    adjacent_target_ = std::string(arg);
                    has_adjacent_ = true;
                    break;
                case PendingValue::Exclude:
                    exclude_targets_.emplace_back(arg);
                    break;
                case PendingValue::Intersect:
                    intersect_target_ = std::string(arg);
                    has_intersect_ = true;
                    break;
                case PendingValue::Split:
                    split_arg_ = std::string(arg);
                    has_split_ = true;
                    break;
                case PendingValue::Nth:
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
            } else if (arg == "--next-prefix") {
                next_prefix_ = true;
            } else if (arg == "--prev-prefix") {
                prev_prefix_ = true;
            } else if (arg == "--aggregate") {
                aggregate_ = true;
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
            } else if (arg == "--relate") {
                pending = PendingValue::Relate;
            } else if (arg.starts_with("--relate=")) {
                relate_target_ = std::string(arg.substr(9));
                has_relate_ = true;
            } else if (arg == "--adjacent") {
                pending = PendingValue::Adjacent;
            } else if (arg.starts_with("--adjacent=")) {
                adjacent_target_ = std::string(arg.substr(11));
                has_adjacent_ = true;
            } else if (arg == "--exclude") {
                pending = PendingValue::Exclude;
            } else if (arg.starts_with("--exclude=")) {
                exclude_targets_.emplace_back(arg.substr(10));
            } else if (arg == "--intersect") {
                pending = PendingValue::Intersect;
            } else if (arg.starts_with("--intersect=")) {
                intersect_target_ = std::string(arg.substr(12));
                has_intersect_ = true;
            } else if (arg == "--split") {
                pending = PendingValue::Split;
            } else if (arg.starts_with("--split=")) {
                split_arg_ = std::string(arg.substr(8));
                has_split_ = true;
            } else if (arg == "--nth") {
                pending = PendingValue::Nth;
            } else if (arg.starts_with("--nth=")) {
                if (!ParseNth(arg.substr(6))) {
                    PrintError("Invalid value for --nth");
                    PrintHelp();
                    return 1;
                }
                has_nth_ = true;
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
        if (pending == PendingValue::Relate) {
            PrintError("Missing value for --relate");
            PrintHelp();
            return 1;
        }
        if (pending == PendingValue::Adjacent) {
            PrintError("Missing value for --adjacent");
            PrintHelp();
            return 1;
        }
        if (pending == PendingValue::Exclude) {
            PrintError("Missing value for --exclude");
            PrintHelp();
            return 1;
        }
        if (pending == PendingValue::Intersect) {
            PrintError("Missing value for --intersect");
            PrintHelp();
            return 1;
        }
        if (pending == PendingValue::Split) {
            PrintError("Missing value for --split");
            PrintHelp();
            return 1;
        }
        if (pending == PendingValue::Nth) {
            PrintError("Missing value for --nth");
            PrintHelp();
            return 1;
        }

        const int exclusive_ops =
            static_cast<int>(has_contains_) + static_cast<int>(has_overlaps_) +
            static_cast<int>(has_relate_) + static_cast<int>(has_adjacent_) +
            static_cast<int>(next_prefix_) + static_cast<int>(prev_prefix_) +
            static_cast<int>(has_intersect_) + static_cast<int>(aggregate_) +
            static_cast<int>(has_split_) + static_cast<int>(has_nth_) +
            static_cast<int>(list_ips_) + static_cast<int>(!exclude_targets_.empty());
        if (exclusive_ops > 1) {
            PrintError("Cannot combine these operations");
            PrintHelp();
            return 1;
        }

        if (has_range_) {
            input_ = range_input_;
            has_input_ = true;
        }

        if (aggregate_ && !read_stdin_) {
            PrintError("--aggregate requires --stdin");
            PrintHelp();
            return 1;
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

        const bool needs_subject = has_contains_ || has_overlaps_ || list_ips_ ||
                                   has_relate_ || has_adjacent_ || next_prefix_ ||
                                   prev_prefix_ || has_intersect_ || has_split_ ||
                                   has_nth_ || !exclude_targets_.empty();

        if (!has_input_) {
            if (interactive_) {
                PrintPrompt();
                if (!std::getline(std::cin, input_)) {
                    return 1;
                }
            } else if (needs_subject) {
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
                return RunRangeOperation(range->first, range->second);
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
            if (has_relate_) {
                return RunRelate(analyzer, relate_target_);
            }
            if (has_adjacent_) {
                return RunAdjacent(analyzer, adjacent_target_);
            }
            if (next_prefix_) {
                return RunPrefixStep(analyzer, true);
            }
            if (prev_prefix_) {
                return RunPrefixStep(analyzer, false);
            }
            if (!exclude_targets_.empty()) {
                return RunExclude(analyzer);
            }
            if (has_intersect_) {
                return RunIntersect(analyzer, intersect_target_);
            }
            if (has_split_) {
                return RunSplit(analyzer);
            }
            if (has_nth_) {
                return RunNth(analyzer);
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
    std::string relate_target_;
    std::string adjacent_target_;
    std::string intersect_target_;
    std::string split_arg_;
    std::vector<std::string> exclude_targets_;
    int64_t nth_index_ = 0;
    bool has_input_ = false;
    bool has_contains_ = false;
    bool has_overlaps_ = false;
    bool has_range_ = false;
    bool has_relate_ = false;
    bool has_adjacent_ = false;
    bool has_intersect_ = false;
    bool has_split_ = false;
    bool has_nth_ = false;
    bool list_ips_ = false;
    bool next_prefix_ = false;
    bool prev_prefix_ = false;
    bool aggregate_ = false;
    bool interactive_ = false;
    bool output_json_ = false;
    bool compact_ = false;
    bool color_enabled_ = true;
    bool read_stdin_ = false;

    bool ParseNth(std::string_view value);
    uint8_t ResolveSplitPrefix(uint8_t parent_cidr, bool ipv4) const;

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
    int RunRelate(const IPAnalyzer &subject, std::string_view other);
    int RunAdjacent(const IPAnalyzer &subject, std::string_view other);
    int RunPrefixStep(const IPAnalyzer &subject, bool next);
    int RunExclude(const IPAnalyzer &subject);
    int RunIntersect(const IPAnalyzer &subject, std::string_view other);
    int RunSplit(const IPAnalyzer &subject);
    int RunNth(const IPAnalyzer &subject);
    int RunListIps(const IPAnalyzer &subject);
    int RunListIpsRange(std::string_view first, std::string_view last);
    int RunRangeToCidr(std::string_view first, std::string_view last);
    int RunRangeOperation(std::string_view first, std::string_view last);
    int RunAggregate(const std::vector<std::string> &inputs);
    void PrintIpListJson(std::string_view network_or_first, std::string_view last,
                         const std::vector<std::string> &hosts, bool is_range) const;
    void PrintRelation(std::string_view operation, std::string_view subject,
                       std::string_view other, std::string_view other_label,
                       bool result) const;
    void PrintNamedRelation(std::string_view subject, std::string_view other,
                            PrefixRelation relation) const;
    void PrintPrefixList(std::string_view operation, const std::vector<std::string> &prefixes) const;
    std::string GetIPv6Scope(const std::shared_ptr<IPAddress> &ip) const;
    void PrintError(const std::string &message) const;
};

}
