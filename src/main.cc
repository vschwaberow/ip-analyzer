#include "ip_analyzer.hh"
#include <fmt/color.h>
#include <fmt/core.h>
#include <iostream>
#include <string>
#include <vector>

namespace
{

    constexpr int kWidth = 80;

    struct OutputColors
    {
        static constexpr auto kHeader = fmt::emphasis::bold | fg(fmt::color::white);
        static constexpr auto kLabel = fg(fmt::color::yellow);
        static constexpr auto kValue = fg(fmt::color::green);
        static constexpr auto kBinary = fg(fmt::color::magenta);
        static constexpr auto kPrompt = fg(fmt::color::cyan) | fmt::emphasis::bold;
        static constexpr auto kError = fg(fmt::color::red) | fmt::emphasis::bold;
    };

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

    void PrintRow(const std::string &label, const std::string &value, const std::string &binary = "")
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

    class IPAnalyzerApp
    {
    public:
        int Run()
        {
            PrintPrompt();
            std::string input;
            if (!std::getline(std::cin, input))
            {
                return 1;
            }

            try
            {
                IPAnalyzer analyzer(input);
                PrintResults(analyzer);
            }
            catch (const std::exception &e)
            {
                PrintError(e.what());
                return 1;
            }

            return 0;
        }

    private:
        void PrintPrompt() const
        {
            fmt::print(OutputColors::kPrompt, "Enter IP address with CIDR (e.g., 192.168.0.1/24): ");
        }

        void PrintResults(const IPAnalyzer &analyzer) const
        {
            PrintHeader("IP Analysis Results");

            const auto [first, last] = analyzer.get_host_range();
            const std::vector<std::tuple<std::string, std::string, std::string>> rows = {
                {"IP Address", analyzer.get_ip().to_string(), analyzer.get_ip().to_binary_string()},
                {"Network Address", analyzer.get_network().to_string(), analyzer.get_network().to_binary_string()},
                {"Netmask", analyzer.get_netmask().to_string(), analyzer.get_netmask().to_binary_string()},
                {"CIDR Notation", "/" + std::to_string(analyzer.get_cidr()), ""},
                {"Broadcast Address", analyzer.get_broadcast().to_string(), ""},
                {"Usable IP Range", (analyzer.get_cidr() == 32) ? analyzer.get_ip().to_string() : fmt::format("{} - {}", first.to_string(), last.to_string()), ""},
                {"Number of Hosts", std::to_string(analyzer.get_num_hosts()), ""},
                {"Private IP", analyzer.is_private() ? "Yes" : "No", ""}};

            for (const auto &[label, value, binary] : rows)
            {
                PrintRow(label, value, binary);
            }

            PrintCopperBar();
        }

        void PrintError(const std::string &message) const
        {
            fmt::print(OutputColors::kError, "Error: {}\n", message);
        }
    };

}

int main()
{
    return IPAnalyzerApp().Run();
}