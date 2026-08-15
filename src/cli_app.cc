// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: src/cli_app.cc
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#include "cli_app.hh"
#include <ranges>

namespace ip_analyzer {

void PrintCopperBar(bool color_enabled)
{
    if (!color_enabled)
    {
        std::println("{}", std::string(kWidth, '='));
        return;
    }

    for (int i : std::views::iota(0, kWidth))
    {
        constexpr int kMaxColor = 255;
        const int r = std::min(kMaxColor, i * kMaxColor / kWidth);
        const int g = std::min(kMaxColor, (kWidth - i) * kMaxColor / kWidth);
        const int b = std::min(kMaxColor, std::abs(kWidth / 2 - i) * 2 * kMaxColor / kWidth);
        std::print("\033[38;2;{};{};{}m█", r, g, b);
    }
    std::println("\033[0m");
}

void PrintHeader(const std::string &text, bool color_enabled)
{
    PrintCopperBar(color_enabled);
    if (color_enabled)
    {
        std::println("{}{:^{}}{}", OutputColors::kHeader, text, kWidth, OutputColors::kReset);
    }
    else
    {
        std::println("{:^{}}", text, kWidth);
    }
    PrintCopperBar(color_enabled);
}

void PrintRow(const std::string &label, const std::string &value, const std::string &binary,
              bool color_enabled)
{
    if (color_enabled)
    {
        std::print("{}{:<20}{}", OutputColors::kLabel, label, OutputColors::kReset);
    }
    else
    {
        std::print("{:<20}", label);
    }
    if (binary.empty())
    {
        if (color_enabled)
        {
            std::println("{}{}{}", OutputColors::kValue, value, OutputColors::kReset);
        }
        else
        {
            std::println("{}", value);
        }
    }
    else
    {
        if (color_enabled)
        {
            std::print("{}{:<20}{}", OutputColors::kValue, value, OutputColors::kReset);
            std::println("{}{}{}", OutputColors::kBinary, binary, OutputColors::kReset);
        }
        else
        {
            std::println("{:<20}{}", value, binary);
        }
    }
}

void IPAnalyzerApp::PrintPrompt() const
{
    if (color_enabled_)
    {
        std::print("{}Enter IP address with CIDR (e.g., 192.168.0.1/24): {}", OutputColors::kPrompt, OutputColors::kReset);
    }
    else
    {
        std::print("Enter IP address with CIDR (e.g., 192.168.0.1/24): ");
    }
    std::fflush(stdout);
}

void IPAnalyzerApp::PrintVersion() const
{
    std::println("{} version {}", kAppName, kVersion);
    std::println("Copyright (c) 2024 {}", kAuthor);
}

void IPAnalyzerApp::PrintHelp() const
{
    PrintVersion();
    std::println("\nUsage: {} [options] [ip-address/cidr]\n", kAppName);
    std::println("Options:");
    std::println("  -h, --help         Show this help message and exit");
    std::println("  -v, --version      Show version information and exit\n");
    std::println("  -i, --interactive  Prompt for IP input interactively");
    std::println("  --json             Output results as JSON");
    std::println("  --compact          Use compact, non-decorated output");
    std::println("  --no-color         Disable colored output");
    std::println("  --stdin            Read IP/CIDR values from stdin");
    std::println("  --ip <value>       Provide the IP/CIDR without prompting\n");
    std::println("Examples:");
    std::println("  {} 192.168.1.1/24", kAppName);
    std::println("  {} 2001:db8::1/64", kAppName);
    std::println("  {} 2001:db8::/64", kAppName);
    std::println("  {} --interactive", kAppName);
}

void IPAnalyzerApp::PrintResults(const IPAnalyzer &analyzer) const
{
    if (!compact_)
    {
        PrintHeader("IP Analysis Results", color_enabled_);
    }

    const auto ip = analyzer.get_ip();
    const auto [first, last] = analyzer.get_host_range();

    std::vector<std::tuple<std::string, std::string, std::string>> rows = {
        {"IP Address", ip->to_string(), ip->to_binary_string()},
        {"Network Address", analyzer.get_network()->to_string(), analyzer.get_network()->to_binary_string()},
        {"Netmask", analyzer.get_netmask()->to_string(), analyzer.get_netmask()->to_binary_string()},
        {"CIDR Notation", "/" + std::to_string(analyzer.get_cidr()), ""},
        {"Subnet Range", std::format("{} - {}", first->to_string(), last->to_string()), ""},
        {"Number of Hosts", std::format("{}", analyzer.get_num_hosts()), ""},
        {"Private IP", analyzer.is_private() ? "Yes" : "No", ""}};

    if (ip->is_ipv6())
    {
        rows.emplace_back("IPv6 Scope", GetIPv6Scope(ip), "");
    }
    else
    {
        rows.emplace_back("Broadcast Address", analyzer.get_broadcast()->to_string(), "");
    }

    if (compact_)
    {
        for (const auto &[label, value, binary] : rows)
        {
            std::println("{}: {}", label, value);
        }
    }
    else
    {
        for (const auto &[label, value, binary] : rows)
        {
            PrintRow(label, value, binary, color_enabled_);
        }
    }

    if (!compact_)
    {
        PrintCopperBar(color_enabled_);
    }
}

void IPAnalyzerApp::PrintJsonResults(const IPAnalyzer &analyzer) const
{
    PrintJsonObject(analyzer, "", false);
}

void IPAnalyzerApp::PrintJsonObject(const IPAnalyzer &analyzer, const std::string &indent,
                                    bool trailing_comma) const
{
    const auto ip = analyzer.get_ip();
    const auto [first, last] = analyzer.get_host_range();

    std::println("{}{{", indent);
    std::println("{}  \"schema\": \"ip-analyzer/1\",", indent);
    std::println("{}  \"version\": \"{}\",", indent, kVersion);
    std::println("{}  \"ip\": \"{}\",", indent, ip->to_string());
    std::println("{}  \"network\": \"{}\",", indent, analyzer.get_network()->to_string());
    std::println("{}  \"netmask\": \"{}\",", indent, analyzer.get_netmask()->to_string());
    std::println("{}  \"cidr\": {},", indent, analyzer.get_cidr());
    std::println("{}  \"range_first\": \"{}\",", indent, first->to_string());
    std::println("{}  \"range_last\": \"{}\",", indent, last->to_string());
    std::println("{}  \"num_hosts\": {},", indent, analyzer.get_num_hosts());
    std::println("{}  \"private\": {},", indent, analyzer.is_private() ? "true" : "false");

    if (ip->is_ipv6())
    {
        std::println("{}  \"scope\": \"{}\"", indent, GetIPv6Scope(ip));
    }
    else
    {
        std::println("{}  \"broadcast\": \"{}\"", indent, analyzer.get_broadcast()->to_string());
    }

    std::println("{}}}{}", indent, trailing_comma ? "," : "");
}

int IPAnalyzerApp::RunFromStdin()
{
    constexpr auto trim_view = [](std::string_view sv) noexcept {
        while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t'))
        {
            sv.remove_prefix(1);
        }
        while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r'))
        {
            sv.remove_suffix(1);
        }
        return sv;
    };

    std::vector<std::string> inputs;
    std::string line;
    while (std::getline(std::cin, line))
    {
        std::string_view trimmed = trim_view(line);
        if (!trimmed.empty())
        {
            inputs.emplace_back(trimmed);
        }
    }

    if (inputs.empty())
    {
        return 1;
    }

    if (output_json_)
    {
        std::println("[");
    }

    for (const auto [index, line] : std::views::enumerate(inputs))
    {
        try
        {
            IPAnalyzer analyzer(line);
            if (output_json_)
            {
                PrintJsonObject(analyzer, "  ", index + 1 < inputs.size());
            }
            else
            {
                if (index > 0)
                {
                    std::print("\n");
                }
                PrintResults(analyzer);
            }
        }
        catch (const std::exception &e)
        {
            if (output_json_)
            {
                std::println("]");
            }
            PrintError(e.what());
            return 1;
        }
    }

    if (output_json_)
    {
        std::println("]");
    }

    return 0;
}

std::string IPAnalyzerApp::GetIPv6Scope(const std::shared_ptr<IPAddress> &ip) const
{
    auto ipv6 = std::dynamic_pointer_cast<IPv6Address>(ip);
    auto bytes = ipv6->to_bytes();
    bool is_unspecified = true;
    for (auto byte : bytes)
    {
        if (byte != 0)
        {
            is_unspecified = false;
            break;
        }
    }
    if (is_unspecified)
        return "Unspecified";
    if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 &&
        bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0 &&
        bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0 && bytes[11] == 0 &&
        bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] == 1)
        return "Loopback";
    if (ipv6->is_ipv4_mapped())
        return "IPv4-Mapped";
    if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
        return "Documentation";
    if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
        return "Link-Local";
    if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0xc0)
        return "Site-Local";
    if (bytes[0] == 0xfd || bytes[0] == 0xfc)
        return "Unique Local";
    if (bytes[0] == 0xff)
        return "Multicast";
    return "Global";
}

void IPAnalyzerApp::PrintError(const std::string &message) const
{
    if (color_enabled_)
    {
        std::println("{}Error: {}{}", OutputColors::kError, message, OutputColors::kReset);
    }
    else
    {
        std::println("Error: {}", message);
    }
}

}
