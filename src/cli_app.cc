// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: src/cli_app.cc
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#include "cli_app.hh"

namespace ip_analyzer {

void PrintCopperBar()
{
    const auto copper_gradient = [](int i)
    {
        constexpr int kMaxColor = 255;
        const int r = std::min(kMaxColor, i * kMaxColor / kWidth);
        const int g = std::min(kMaxColor, (kWidth - i) * kMaxColor / kWidth);
        const int b = std::min(kMaxColor, std::abs(kWidth / 2 - i) * 2 * kMaxColor / kWidth);
        return fmt::rgb(r, g, b);
    };

    for (int i = 0; i < kWidth; ++i)
    {
        fmt::print(fg(copper_gradient(i)), "█");
    }
    fmt::print("\n");
}

void PrintHeader(const std::string &text)
{
    PrintCopperBar();
    fmt::print(OutputColors::kHeader, "{:^{}}\n", text, kWidth);
    PrintCopperBar();
}

void PrintRow(const std::string &label, const std::string &value, const std::string &binary)
{
    fmt::print(OutputColors::kLabel, "{:<20}", label);
    if (binary.empty())
    {
        fmt::print(OutputColors::kValue, "{}\n", value);
    }
    else
    {
        fmt::print(OutputColors::kValue, "{:<20}", value);
        fmt::print(OutputColors::kBinary, "{}\n", binary);
    }
}

void IPAnalyzerApp::PrintPrompt() const
{
    fmt::print(OutputColors::kPrompt, "Enter IP address with CIDR (e.g., 192.168.0.1/24): ");
}

void IPAnalyzerApp::PrintVersion() const
{
    std::cout << fmt::format("{} version {}\n", kAppName, kVersion);
    std::cout << fmt::format("Copyright (c) 2024 {}\n", kAuthor);
}

void IPAnalyzerApp::PrintHelp() const
{
    PrintVersion();
    fmt::print("\nUsage: {} [options] [ip-address/cidr]\n\n", kAppName);
    fmt::print("Options:\n");
    fmt::print("  -h, --help     Show this help message and exit\n");
    fmt::print("  -v, --version  Show version information and exit\n\n");
    fmt::print("  --json         Output results as JSON\n");
    fmt::print("  --ip <value>   Provide the IP/CIDR without prompting\n\n");
    fmt::print("Examples:\n");
    fmt::print("  {} 192.168.1.1/24\n", kAppName);
    fmt::print("  {} 2001:db8::1/64\n", kAppName);
}

void IPAnalyzerApp::PrintResults(const IPAnalyzer &analyzer) const
{
    PrintHeader("IP Analysis Results");

    const auto ip = analyzer.get_ip();
    const auto [first, last] = analyzer.get_host_range();

    std::vector<std::tuple<std::string, std::string, std::string>> rows = {
        {"IP Address", ip->to_string(), ip->to_binary_string()},
        {"Network Address", analyzer.get_network()->to_string(), analyzer.get_network()->to_binary_string()},
        {"Netmask", analyzer.get_netmask()->to_string(), analyzer.get_netmask()->to_binary_string()},
        {"CIDR Notation", "/" + std::to_string(analyzer.get_cidr()), ""},
        {"Subnet Range", fmt::format("{} - {}", first->to_string(), last->to_string()), ""},
        {"Number of Hosts", fmt::format("{}", analyzer.get_num_hosts()), ""},
        {"Private IP", analyzer.is_private() ? "Yes" : "No", ""}};

    if (ip->is_ipv6())
    {
        rows.emplace_back("IPv6 Scope", GetIPv6Scope(ip), "");
    }
    else
    {
        rows.emplace_back("Broadcast Address", analyzer.get_broadcast()->to_string(), "");
    }

    for (const auto &[label, value, binary] : rows)
    {
        PrintRow(label, value, binary);
    }

    PrintCopperBar();
}

void IPAnalyzerApp::PrintJsonResults(const IPAnalyzer &analyzer) const
{
    const auto ip = analyzer.get_ip();
    const auto [first, last] = analyzer.get_host_range();

    fmt::print("{{\n");
    fmt::print("  \"ip\": \"{}\",\n", ip->to_string());
    fmt::print("  \"network\": \"{}\",\n", analyzer.get_network()->to_string());
    fmt::print("  \"netmask\": \"{}\",\n", analyzer.get_netmask()->to_string());
    fmt::print("  \"cidr\": {},\n", analyzer.get_cidr());
    fmt::print("  \"range_first\": \"{}\",\n", first->to_string());
    fmt::print("  \"range_last\": \"{}\",\n", last->to_string());
    fmt::print("  \"num_hosts\": {},\n", analyzer.get_num_hosts());
    fmt::print("  \"private\": {},\n", analyzer.is_private() ? "true" : "false");

    if (ip->is_ipv6())
    {
        fmt::print("  \"scope\": \"{}\"\n", GetIPv6Scope(ip));
    }
    else
    {
        fmt::print("  \"broadcast\": \"{}\"\n", analyzer.get_broadcast()->to_string());
    }

    fmt::print("}}\n");
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
    fmt::print(OutputColors::kError, "Error: {}\n", message);
}

}
