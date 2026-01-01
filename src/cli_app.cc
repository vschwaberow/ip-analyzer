// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: src/cli_app.cc
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#include "cli_app.hh"

namespace ip_analyzer {

void PrintCopperBar(bool color_enabled)
{
    if (!color_enabled)
    {
        fmt::print("{}\n", std::string(kWidth, '='));
        return;
    }

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

void PrintHeader(const std::string &text, bool color_enabled)
{
    PrintCopperBar(color_enabled);
    if (color_enabled)
    {
        fmt::print(OutputColors::kHeader, "{:^{}}\n", text, kWidth);
    }
    else
    {
        fmt::print("{:^{}}\n", text, kWidth);
    }
    PrintCopperBar(color_enabled);
}

void PrintRow(const std::string &label, const std::string &value, const std::string &binary,
              bool color_enabled)
{
    if (color_enabled)
    {
        fmt::print(OutputColors::kLabel, "{:<20}", label);
    }
    else
    {
        fmt::print("{:<20}", label);
    }
    if (binary.empty())
    {
        if (color_enabled)
        {
            fmt::print(OutputColors::kValue, "{}\n", value);
        }
        else
        {
            fmt::print("{}\n", value);
        }
    }
    else
    {
        if (color_enabled)
        {
            fmt::print(OutputColors::kValue, "{:<20}", value);
            fmt::print(OutputColors::kBinary, "{}\n", binary);
        }
        else
        {
            fmt::print("{:<20}{}\n", value, binary);
        }
    }
}

void IPAnalyzerApp::PrintPrompt() const
{
    if (color_enabled_)
    {
        fmt::print(OutputColors::kPrompt, "Enter IP address with CIDR (e.g., 192.168.0.1/24): ");
    }
    else
    {
        fmt::print("Enter IP address with CIDR (e.g., 192.168.0.1/24): ");
    }
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
    fmt::print("  --compact      Use compact, non-decorated output\n");
    fmt::print("  --no-color     Disable colored output\n");
    fmt::print("  --stdin        Read IP/CIDR values from stdin\n");
    fmt::print("  --ip <value>   Provide the IP/CIDR without prompting\n\n");
    fmt::print("Examples:\n");
    fmt::print("  {} 192.168.1.1/24\n", kAppName);
    fmt::print("  {} 2001:db8::1/64\n", kAppName);
    fmt::print("  {} 2001:db8::/64\n", kAppName);
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

    if (compact_)
    {
        for (const auto &[label, value, binary] : rows)
        {
            fmt::print("{}: {}\n", label, value);
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

    fmt::print("{}{{\n", indent);
    fmt::print("{}  \"schema\": \"ip-analyzer/1\",\n", indent);
    fmt::print("{}  \"version\": \"{}\",\n", indent, kVersion);
    fmt::print("{}  \"ip\": \"{}\",\n", indent, ip->to_string());
    fmt::print("{}  \"network\": \"{}\",\n", indent, analyzer.get_network()->to_string());
    fmt::print("{}  \"netmask\": \"{}\",\n", indent, analyzer.get_netmask()->to_string());
    fmt::print("{}  \"cidr\": {},\n", indent, analyzer.get_cidr());
    fmt::print("{}  \"range_first\": \"{}\",\n", indent, first->to_string());
    fmt::print("{}  \"range_last\": \"{}\",\n", indent, last->to_string());
    fmt::print("{}  \"num_hosts\": {},\n", indent, analyzer.get_num_hosts());
    fmt::print("{}  \"private\": {},\n", indent, analyzer.is_private() ? "true" : "false");

    if (ip->is_ipv6())
    {
        fmt::print("{}  \"scope\": \"{}\"\n", indent, GetIPv6Scope(ip));
    }
    else
    {
        fmt::print("{}  \"broadcast\": \"{}\"\n", indent, analyzer.get_broadcast()->to_string());
    }

    fmt::print("{}}}{}\n", indent, trailing_comma ? "," : "");
}

int IPAnalyzerApp::RunFromStdin()
{
    std::vector<std::string> inputs;
    std::string line;
    while (std::getline(std::cin, line))
    {
        if (!line.empty())
        {
            inputs.push_back(line);
        }
    }

    if (inputs.empty())
    {
        return 1;
    }

    if (output_json_)
    {
        fmt::print("[\n");
    }

    for (size_t index = 0; index < inputs.size(); ++index)
    {
        try
        {
            IPAnalyzer analyzer(inputs[index]);
            if (output_json_)
            {
                PrintJsonObject(analyzer, "  ", index + 1 < inputs.size());
            }
            else
            {
                if (index > 0)
                {
                    fmt::print("\n");
                }
                PrintResults(analyzer);
            }
        }
        catch (const std::exception &e)
        {
            if (output_json_)
            {
                fmt::print("]\n");
            }
            PrintError(e.what());
            return 1;
        }
    }

    if (output_json_)
    {
        fmt::print("]\n");
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
        fmt::print(OutputColors::kError, "Error: {}\n", message);
    }
    else
    {
        fmt::print("Error: {}\n", message);
    }
}

}
