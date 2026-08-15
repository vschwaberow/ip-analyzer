// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: src/ip_analyzer.cc
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#include "ip_analyzer.hh"
#include <stdexcept>
#include <sstream>
#include <bitset>
#include <bit>
#include <compare>
#include <algorithm>
#include <ranges>
#include <regex>
#include <vector>
#include <iomanip>
#include <limits>
#include <charconv>
#include <system_error>
#include <optional>
#include <utility>

uint32_t IPAnalyzer::calculate_ipv4_network(uint32_t ip_int, uint8_t cidr)
{
    if (cidr == 0)
    {
        return 0;
    }
    uint32_t mask = 0xFFFFFFFFU << (32 - cidr);
    return ip_int & mask;
}

uint32_t IPAnalyzer::calculate_ipv4_broadcast(uint32_t ip_int, uint8_t cidr)
{
    if (cidr == 0)
    {
        return 0xFFFFFFFFU;
    }
    uint32_t mask = 0xFFFFFFFFU << (32 - cidr);
    return ip_int | ~mask;
}

IPv6Address::IPv6Address(std::string_view address)
{
    bool is_ipv4_mapped = false;
    std::string converted_address;
    if (address.find('.') != std::string_view::npos)
    {
        converted_address = convert_ipv4_mapped(address);
        address = converted_address;
        is_ipv4_mapped = true;
    }

    std::string expanded_address = expand_ipv6_address(address);
    std::fill(bytes_.begin(), bytes_.end(), 0);

    std::istringstream iss(expanded_address);
    std::string group;
    size_t i = 0;
    while (std::getline(iss, group, ':') && i < 16)
    {
        if (!group.empty())
        {
            uint16_t value = std::stoi(group, nullptr, 16);
            bytes_[i++] = static_cast<uint8_t>(value >> 8);
            bytes_[i++] = static_cast<uint8_t>(value & 0xFF);
        }
    }

    if (i != 16)
    {
        throw std::invalid_argument("Invalid IPv6 address format");
    }

    if (is_ipv4_mapped)
    {
        if (std::ranges::any_of(bytes_ | std::views::take(10),
                                [](uint8_t byte) { return byte != 0; }))
        {
            throw std::invalid_argument("Only IPv4-mapped IPv6 addresses are supported");
        }
        if (bytes_[10] != 0xFF || bytes_[11] != 0xFF)
        {
            throw std::invalid_argument("Only IPv4-mapped IPv6 addresses are supported");
        }
    }
}

std::string IPv6Address::convert_ipv4_mapped(std::string_view address)
{
    size_t last_colon = address.rfind(':');
    if (last_colon == std::string_view::npos)
    {
        throw std::invalid_argument("Invalid IPv6 address format");
    }

    std::string_view ipv4_part = address.substr(last_colon + 1);
    std::string_view prefix = address.substr(0, last_colon);

    std::array<uint8_t, 4> octets{};
    size_t start = 0;
    int index = 0;
    while (start <= ipv4_part.size())
    {
        if (index >= 4)
        {
            throw std::invalid_argument("Invalid IPv4-mapped IPv6 address format");
        }

        size_t end = ipv4_part.find('.', start);
        std::string_view segment = (end == std::string_view::npos)
                                       ? ipv4_part.substr(start)
                                       : ipv4_part.substr(start, end - start);
        if (segment.empty())
        {
            throw std::invalid_argument("Invalid IPv4-mapped IPv6 address format");
        }

        uint32_t value = 0;
        const auto [ptr, ec] = std::from_chars(segment.data(), segment.data() + segment.size(), value);
        if (ec != std::errc{} || ptr != segment.data() + segment.size() || value > 255)
        {
            throw std::invalid_argument("Invalid IPv4-mapped IPv6 address format");
        }

        octets[index++] = static_cast<uint8_t>(value);

        if (end == std::string_view::npos)
        {
            break;
        }
        start = end + 1;
    }

    if (index != 4)
    {
        throw std::invalid_argument("Invalid IPv4-mapped IPv6 address format");
    }

    uint16_t high = static_cast<uint16_t>((octets[0] << 8) | octets[1]);
    uint16_t low = static_cast<uint16_t>((octets[2] << 8) | octets[3]);

    char high_buffer[5];
    char low_buffer[5];
    std::snprintf(high_buffer, sizeof(high_buffer), "%04x", high);
    std::snprintf(low_buffer, sizeof(low_buffer), "%04x", low);

    std::string result;
    if (!prefix.empty())
    {
        result.append(prefix);
        if (!prefix.ends_with(':'))
        {
            result.push_back(':');
        }
    }
    result.append(high_buffer);
    result.push_back(':');
    result.append(low_buffer);
    return result;
}


std::string IPv6Address::expand_ipv6_address(std::string_view address) {
    if (address.empty()) {
        throw std::invalid_argument("IPv6 address cannot be empty");
    }

    if (address.find(":::") != std::string_view::npos) {
        throw std::invalid_argument("Invalid IPv6 address format: ':::' found");
    }

    size_t double_colon_pos = address.find("::");
    bool has_double_colon = double_colon_pos != std::string_view::npos;
    
    if (has_double_colon && address.find("::", double_colon_pos + 2) != std::string_view::npos) {
        throw std::invalid_argument("Invalid IPv6 address format: multiple '::' occurrences");
    }

    auto split_segments = [](std::string_view input) {
        std::vector<std::string_view> segments;
        size_t start = 0;
        while (start <= input.size()) {
            size_t end = input.find(':', start);
            std::string_view segment = (end == std::string_view::npos)
                                           ? input.substr(start)
                                           : input.substr(start, end - start);
            if (segment.empty()) {
                throw std::invalid_argument("Invalid IPv6 address format");
            }
            segments.push_back(segment);
            if (end == std::string_view::npos) {
                break;
            }
            start = end + 1;
        }
        return segments;
    };

    auto pad_segment = [](std::string_view segment) {
        if (segment.empty()) {
            return std::string("0000");
        }
        if (segment.size() > 4) {
            throw std::invalid_argument("Invalid IPv6 address format: segment too long");
        }
        int value = 0;
        for (char c : segment) {
            int digit = hex_char_to_int(c);
            if (digit < 0) {
                throw std::invalid_argument("Invalid IPv6 address format: non-hex digit");
            }
            value = (value << 4) + digit;
        }
        char hex_buffer[5];
        std::snprintf(hex_buffer, sizeof(hex_buffer), "%04x", value);
        return std::string(hex_buffer);
    };

    std::vector<std::string_view> segments;
    if (has_double_colon) {
        std::string_view before = address.substr(0, double_colon_pos);
        std::string_view after = address.substr(double_colon_pos + 2);

        if (!before.empty()) {
            auto before_segments = split_segments(before);
            segments.insert(segments.end(), before_segments.begin(), before_segments.end());
        }

        std::vector<std::string_view> after_segments;
        if (!after.empty()) {
            after_segments = split_segments(after);
        }

        int explicit_segments = static_cast<int>(segments.size() + after_segments.size());
        int missing_segments = 8 - explicit_segments;
        if (missing_segments < 1) {
            throw std::invalid_argument("Invalid IPv6 address format: too many segments");
        }

        segments.resize(segments.size() + static_cast<size_t>(missing_segments));
        segments.insert(segments.end(), after_segments.begin(), after_segments.end());
    } else {
        segments = split_segments(address);
        if (segments.size() != 8) {
            throw std::invalid_argument("Invalid IPv6 address format: incorrect segment count");
        }
    }

    std::string result;
    result.reserve(39);
    for (size_t i : std::views::iota(size_t{0}, segments.size())) {
        if (i > 0) {
            result.push_back(':');
        }
        result.append(pad_segment(segments[i]));
    }

    return result;
}

constexpr int IPv6Address::hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

IPv6Address::IPv6Address(const std::array<uint8_t, 16> &bytes) : bytes_(bytes) {}

bool IPv6Address::is_ipv4_mapped() const
{
    return std::ranges::all_of(bytes_ | std::views::take(10),
                               [](uint8_t byte) { return byte == 0; })
           && bytes_[10] == 0xFF && bytes_[11] == 0xFF;
}

std::string IPv6Address::to_string() const
{
    if (is_ipv4_mapped())
    {
        std::ostringstream oss;
        oss << "::ffff:";
        oss << static_cast<int>(bytes_[12]) << '.'
            << static_cast<int>(bytes_[13]) << '.'
            << static_cast<int>(bytes_[14]) << '.'
            << static_cast<int>(bytes_[15]);
        return oss.str();
    }

    std::array<uint16_t, 8> groups{};
    for (size_t i : std::views::iota(size_t{0}, groups.size()))
    {
        groups[i] = static_cast<uint16_t>((bytes_[i * 2] << 8) | bytes_[i * 2 + 1]);
    }

    size_t best_start = 0;
    size_t best_len = 0;
    size_t current_start = 0;
    size_t current_len = 0;
    for (size_t i : std::views::iota(size_t{0}, groups.size()))
    {
        if (groups[i] == 0)
        {
            if (current_len == 0)
            {
                current_start = i;
            }
            current_len++;
        }
        else
        {
            if (current_len > best_len)
            {
                best_start = current_start;
                best_len = current_len;
            }
            current_len = 0;
        }
    }
    if (current_len > best_len)
    {
        best_start = current_start;
        best_len = current_len;
    }
    if (best_len < 2)
    {
        best_len = 0;
    }

    std::ostringstream oss;
    for (size_t i : std::views::iota(size_t{0}, groups.size()))
    {
        if (best_len > 0 && i >= best_start && i < best_start + best_len)
        {
            if (i == best_start)
            {
                oss << "::";
            }
            continue;
        }

        if (i > 0 && !(best_len > 0 && i == best_start + best_len))
        {
            oss << ':';
        }
        oss << std::hex << std::nouppercase << groups[i];
    }

    std::string result = oss.str();
    if (result.empty())
    {
        return "::";
    }
    return result;
}

std::string IPv6Address::to_binary_string() const
{
    std::ostringstream oss;
    for (auto byte : bytes_)
    {
        oss << std::bitset<8>(byte).to_string();
    }
    return oss.str();
}

bool IPv6Address::is_private() const
{
    if (is_ipv4_mapped())
    {
        const uint32_t embedded =
            (static_cast<uint32_t>(bytes_[12]) << 24) |
            (static_cast<uint32_t>(bytes_[13]) << 16) |
            (static_cast<uint32_t>(bytes_[14]) << 8) |
            static_cast<uint32_t>(bytes_[15]);
        return IPv4Address(embedded).is_private();
    }
    return bytes_[0] == 0xFD || bytes_[0] == 0xFC;
}

std::array<uint8_t, 16> IPv6Address::to_bytes() const
{
    return bytes_;
}

IPAnalyzer::IPAnalyzer(std::string_view ip_cidr)
{
    constexpr auto is_space = [](char c) noexcept {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    };

    constexpr auto trim = [is_space](std::string_view sv) noexcept {
        while (!sv.empty() && is_space(sv.front()))
        {
            sv.remove_prefix(1);
        }
        while (!sv.empty() && is_space(sv.back()))
        {
            sv.remove_suffix(1);
        }
        return sv;
    };

    ip_cidr = trim(ip_cidr);

    if (ip_cidr.empty())
    {
        throw std::invalid_argument("Empty IP address input");
    }

    auto slash_pos = ip_cidr.find('/');
    std::string_view ip_str;

    if (slash_pos == std::string_view::npos)
    {
        ip_str = ip_cidr;
        cidr_ = ip_cidr.contains(':') ? 128 : 32;
    }
    else
    {
        ip_str = trim(ip_cidr.substr(0, slash_pos));
        const std::string_view cidr_str = trim(ip_cidr.substr(slash_pos + 1));

        uint32_t cidr_value{};
        if (cidr_str.find('.') != std::string_view::npos)
        {
            if (ip_str.contains(':'))
            {
                throw std::invalid_argument("IPv4 netmask cannot be used with IPv6");
            }
            IPv4Address netmask(cidr_str);
            uint32_t mask = netmask.to_uint32();
            int leading_ones = std::countl_one(mask);
            int trailing_zeros = std::countr_zero(mask);
            if (leading_ones + trailing_zeros != 32)
            {
                throw std::invalid_argument("Invalid IPv4 netmask");
            }
            cidr_value = static_cast<uint32_t>(leading_ones);
        }
        else
        {
            const auto result = std::from_chars(cidr_str.data(), cidr_str.data() + cidr_str.size(), cidr_value);
            if (result.ec != std::errc{} || result.ptr != cidr_str.data() + cidr_str.size())
            {
                throw std::invalid_argument("Invalid CIDR format");
            }
        }

        if (ip_str.contains(':'))
        {
            if (cidr_value > 128)
            {
                throw std::invalid_argument("Invalid IPv6 CIDR value");
            }
        }
        else
        {
            if (cidr_value > 32)
            {
                throw std::invalid_argument("Invalid IPv4 CIDR value");
            }
        }

        cidr_ = static_cast<uint8_t>(cidr_value);
    }

    if (ip_str.contains(':'))
    {
        ip_ = std::make_shared<IPv6Address>(ip_str);
    }
    else
    {
        ip_ = std::make_shared<IPv4Address>(ip_str);
    }
}

std::shared_ptr<IPAddress> IPAnalyzer::get_ip() const
{
    return ip_;
}

std::shared_ptr<IPAddress> IPAnalyzer::get_network() const
{
    if (ip_->is_ipv4())
    {
        auto ipv4 = std::dynamic_pointer_cast<IPv4Address>(ip_);
        uint32_t ip_int = ipv4->to_uint32();
        uint32_t network = IPAnalyzer::calculate_ipv4_network(ip_int, cidr_);
        return std::make_shared<IPv4Address>(network);
    }
    else
    {
        auto ipv6 = std::dynamic_pointer_cast<IPv6Address>(ip_);
        std::array<uint8_t, 16> ip_bytes = ipv6->to_bytes();
        std::array<uint8_t, 16> network_bytes = ip_bytes;

        int fullBytes = cidr_ / 8;
        int remainingBits = cidr_ % 8;

        if (remainingBits > 0)
        {
            network_bytes[fullBytes] &= static_cast<uint8_t>(0xFF << (8 - remainingBits));
        }

        const auto host_offset =
            static_cast<size_t>(fullBytes + (remainingBits > 0 ? 1 : 0));
        std::ranges::fill(network_bytes | std::views::drop(host_offset), 0);

        return std::make_shared<IPv6Address>(network_bytes);
    }
}

std::shared_ptr<IPAddress> IPAnalyzer::get_netmask() const
{
    if (ip_->is_ipv4())
    {
        uint32_t mask = cidr_ == 0 ? 0 : 0xFFFFFFFF << (32 - cidr_);
        return std::make_shared<IPv4Address>(mask);
    }
    else
    {
        std::array<uint8_t, 16> mask;
        int fullBytes = cidr_ / 8;
        int remainingBits = cidr_ % 8;

        std::fill_n(mask.begin(), fullBytes, 0xFF);

        if (remainingBits > 0)
        {
            mask[fullBytes] = static_cast<uint8_t>(0xFF << (8 - remainingBits));
        }

        std::fill(mask.begin() + fullBytes + (remainingBits > 0 ? 1 : 0), mask.end(), 0);

        return std::make_shared<IPv6Address>(mask);
    }
}

std::shared_ptr<IPAddress> IPAnalyzer::get_broadcast() const
{
    if (ip_->is_ipv4())
    {
        auto ipv4 = std::dynamic_pointer_cast<IPv4Address>(ip_);
        uint32_t ip_int = ipv4->to_uint32();
        uint32_t broadcast = IPAnalyzer::calculate_ipv4_broadcast(ip_int, cidr_);
        return std::make_shared<IPv4Address>(broadcast);
    }
    else
    {
        auto ipv6 = std::dynamic_pointer_cast<IPv6Address>(ip_);
        std::array<uint8_t, 16> ip_bytes = ipv6->to_bytes();
        int fullBytes = cidr_ / 8;
        int remainingBits = cidr_ % 8;

        if (remainingBits > 0)
        {
            ip_bytes[fullBytes] &= static_cast<uint8_t>(0xFF << (8 - remainingBits));
        }

        const auto host_offset =
            static_cast<size_t>(fullBytes + (remainingBits > 0 ? 1 : 0));
        std::ranges::fill(ip_bytes | std::views::drop(host_offset), 0xFF);

        if (remainingBits > 0)
        {
            ip_bytes[fullBytes] |= static_cast<uint8_t>(0xFF >> remainingBits);
        }

        return std::make_shared<IPv6Address>(ip_bytes);
    }
}

std::pair<std::shared_ptr<IPAddress>, std::shared_ptr<IPAddress>> IPAnalyzer::get_host_range() const
{
    if (ip_->is_ipv4())
    {
        auto ipv4 = std::dynamic_pointer_cast<IPv4Address>(ip_);
        uint32_t ip_int = ipv4->to_uint32();
        uint32_t mask = cidr_ == 0 ? 0 : 0xFFFFFFFF << (32 - cidr_);
        uint32_t network = ip_int & mask;
        uint32_t broadcast = ip_int | ~mask;

        uint32_t first_host = (cidr_ == 32 || cidr_ == 31) ? network : network + 1;
        uint32_t last_host = (cidr_ == 32 || cidr_ == 31) ? broadcast : broadcast - 1;

        return {
            std::make_shared<IPv4Address>(first_host),
            std::make_shared<IPv4Address>(last_host)};
    }
    else
    {
        auto network = get_network();
        auto ipv6_network = std::dynamic_pointer_cast<IPv6Address>(network);
        std::array<uint8_t, 16> network_bytes = ipv6_network->to_bytes();
        std::array<uint8_t, 16> last_bytes = network_bytes;

        int fullBytes = cidr_ / 8;
        int remainingBits = cidr_ % 8;

        if (remainingBits > 0)
        {
            last_bytes[fullBytes] |= static_cast<uint8_t>(0xFF >> remainingBits);
        }
        const auto host_offset =
            static_cast<size_t>(fullBytes + (remainingBits > 0 ? 1 : 0));
        std::ranges::fill(last_bytes | std::views::drop(host_offset), 0xFF);

        if (cidr_ < 127)
        {
            for (uint8_t& byte : network_bytes | std::views::reverse)
            {
                if (++byte != 0)
                {
                    break;
                }
            }

            for (uint8_t& byte : last_bytes | std::views::reverse)
            {
                if (--byte != 0xFF)
                {
                    break;
                }
            }
        }

        return {
            std::make_shared<IPv6Address>(network_bytes),
            std::make_shared<IPv6Address>(last_bytes)};
    }
}

uint64_t IPAnalyzer::get_num_hosts() const
{
    if (ip_->is_ipv4())
    {
        if (cidr_ >= 31)
        {
            return cidr_ == 31 ? 2 : 1;
        }
        return (1ULL << (32 - cidr_)) - 2;
    }
    else
    {
        if (cidr_ >= 127)
        {
            return cidr_ == 127 ? 2 : 1;
        }

        if (cidr_ < 64)
        {
            return std::numeric_limits<uint64_t>::max();
        }

        if (cidr_ == 64)
        {
            return std::numeric_limits<uint64_t>::max() - 1;
        }

        return (1ULL << (128 - cidr_)) - 2;
    }
}

bool IPAnalyzer::is_private() const
{
    return ip_->is_private();
}

uint8_t IPAnalyzer::get_cidr() const
{
    return cidr_;
}

IPv4Address::IPv4Address(std::string_view address)
{
    int i = 0;
    size_t start = 0;
    while (start <= address.size())
    {
        if (i >= 4)
        {
            throw std::invalid_argument("Invalid IPv4 address format");
        }

        size_t end = address.find('.', start);
        std::string_view segment = (end == std::string_view::npos)
                                       ? address.substr(start)
                                       : address.substr(start, end - start);
        if (segment.empty())
        {
            throw std::invalid_argument("Invalid IPv4 address format");
        }

        uint32_t value = 0;
        const auto [ptr, ec] = std::from_chars(segment.data(), segment.data() + segment.size(), value);
        if (ec != std::errc{} || ptr != segment.data() + segment.size())
        {
            throw std::invalid_argument("Invalid IPv4 address format");
        }
        if (value > 255)
        {
            throw std::invalid_argument("Invalid octet value");
        }

        octets_[i++] = static_cast<uint8_t>(value);

        if (end == std::string_view::npos)
        {
            break;
        }
        start = end + 1;
    }
    if (i != 4)
    {
        throw std::invalid_argument("Invalid IPv4 address format");
    }
}

IPv4Address::IPv4Address(unsigned int address)
{
    for (uint8_t& octet : octets_ | std::views::reverse)
    {
        octet = static_cast<uint8_t>(address & 0xFF);
        address >>= 8;
    }
}

uint32_t IPv4Address::to_uint32() const
{
    return (static_cast<uint32_t>(octets_[0]) << 24) |
           (static_cast<uint32_t>(octets_[1]) << 16) |
           (static_cast<uint32_t>(octets_[2]) << 8) |
           static_cast<uint32_t>(octets_[3]);
}

std::string IPv4Address::to_string() const
{
    std::ostringstream oss;
    oss << static_cast<int>(octets_[0]) << '.'
        << static_cast<int>(octets_[1]) << '.'
        << static_cast<int>(octets_[2]) << '.'
        << static_cast<int>(octets_[3]);
    return oss.str();
}

std::string IPv4Address::to_binary_string() const
{
    std::ostringstream oss;
    for (const uint8_t octet : octets_)
    {
        oss << std::bitset<8>(octet).to_string();
    }
    return oss.str();
}

bool IPv4Address::is_private() const
{
    uint32_t ip = to_uint32();
    return (ip & 0xFF000000) == 0x0A000000 ||
           (ip & 0xFFF00000) == 0xAC100000 ||
           (ip & 0xFFFF0000) == 0xC0A80000;
}

namespace {

constexpr bool is_space(char c) noexcept
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

std::string_view trim_view(std::string_view sv) noexcept
{
    while (!sv.empty() && is_space(sv.front()))
    {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && is_space(sv.back()))
    {
        sv.remove_suffix(1);
    }
    return sv;
}

std::array<uint8_t, 16> apply_ipv6_prefix(std::array<uint8_t, 16> bytes, uint8_t cidr)
{
    const int full_bytes = cidr / 8;
    const int remaining_bits = cidr % 8;
    if (remaining_bits > 0)
    {
        bytes[full_bytes] &= static_cast<uint8_t>(0xFF << (8 - remaining_bits));
    }
    const auto host_offset =
        static_cast<size_t>(full_bytes + (remaining_bits > 0 ? 1 : 0));
    std::ranges::fill(bytes | std::views::drop(host_offset), 0);
    return bytes;
}

void increment_ipv6(std::array<uint8_t, 16> &bytes)
{
    for (uint8_t &byte : bytes | std::views::reverse)
    {
        if (++byte != 0)
        {
            break;
        }
    }
}

struct UInt128
{
    uint64_t hi{0};
    uint64_t lo{0};

    static UInt128 from_u64(uint64_t value) { return {0, value}; }

    static UInt128 from_bytes(const std::array<uint8_t, 16> &bytes)
    {
        UInt128 value;
        for (int i = 0; i < 8; ++i)
        {
            value.hi = (value.hi << 8) | bytes[static_cast<size_t>(i)];
            value.lo = (value.lo << 8) | bytes[static_cast<size_t>(i + 8)];
        }
        return value;
    }

    [[nodiscard]] std::array<uint8_t, 16> to_bytes() const
    {
        std::array<uint8_t, 16> bytes{};
        uint64_t high = hi;
        uint64_t low = lo;
        for (int i = 7; i >= 0; --i)
        {
            bytes[static_cast<size_t>(i)] = static_cast<uint8_t>(high & 0xFF);
            bytes[static_cast<size_t>(i + 8)] = static_cast<uint8_t>(low & 0xFF);
            high >>= 8;
            low >>= 8;
        }
        return bytes;
    }

    friend constexpr bool operator==(const UInt128 &, const UInt128 &) = default;
    friend constexpr std::strong_ordering operator<=>(const UInt128 &lhs,
                                                      const UInt128 &rhs)
    {
        if (lhs.hi != rhs.hi)
        {
            return lhs.hi <=> rhs.hi;
        }
        return lhs.lo <=> rhs.lo;
    }

    [[nodiscard]] UInt128 operator+(const UInt128 &other) const
    {
        UInt128 result;
        result.lo = lo + other.lo;
        result.hi = hi + other.hi + (result.lo < lo ? 1 : 0);
        return result;
    }

    [[nodiscard]] UInt128 operator-(const UInt128 &other) const
    {
        UInt128 result;
        result.lo = lo - other.lo;
        result.hi = hi - other.hi - (lo < other.lo ? 1 : 0);
        return result;
    }

    [[nodiscard]] UInt128 operator<<(int shift) const
    {
        if (shift <= 0)
        {
            return *this;
        }
        if (shift >= 128)
        {
            return {};
        }
        if (shift >= 64)
        {
            return {lo << (shift - 64), 0};
        }
        return {(hi << shift) | (lo >> (64 - shift)), lo << shift};
    }

    [[nodiscard]] int countr_zero() const
    {
        if (lo != 0)
        {
            return static_cast<int>(std::countr_zero(lo));
        }
        if (hi != 0)
        {
            return 64 + static_cast<int>(std::countr_zero(hi));
        }
        return 128;
    }

    [[nodiscard]] int bit_width() const
    {
        if (hi != 0)
        {
            return 64 + static_cast<int>(std::bit_width(hi));
        }
        return static_cast<int>(std::bit_width(lo));
    }
};

std::vector<std::string> summarize_ipv4(uint32_t start, uint32_t end)
{
    std::vector<std::string> prefixes;
    while (start <= end)
    {
        if (start == 0 && end == 0xFFFFFFFFU)
        {
            prefixes.emplace_back("0.0.0.0/0");
            break;
        }

        const int align_bits = (start == 0) ? 32 : std::countr_zero(start);
        const uint32_t remaining = end - start;
        const int size_bits = (remaining == 0xFFFFFFFFU && start == 0)
                                  ? 32
                                  : static_cast<int>(std::bit_width(remaining + 1U)) - 1;
        const int host_bits = std::min(align_bits, size_bits);
        const int prefix = 32 - host_bits;
        prefixes.push_back(IPv4Address(start).to_string() + "/" + std::to_string(prefix));

        if (host_bits == 32)
        {
            break;
        }
        const uint32_t block = 1U << host_bits;
        if (start > 0xFFFFFFFFU - block)
        {
            break;
        }
        start += block;
    }
    return prefixes;
}

std::vector<std::string> summarize_ipv6(UInt128 start, UInt128 end)
{
    std::vector<std::string> prefixes;
    const UInt128 max{~0ULL, ~0ULL};
    const UInt128 one = UInt128::from_u64(1);

    while (start <= end)
    {
        if (start == UInt128{} && end == max)
        {
            prefixes.emplace_back("::/0");
            break;
        }

        const int align_bits = (start == UInt128{}) ? 128 : start.countr_zero();
        const UInt128 remaining = end - start;
        const int size_bits = (remaining == max)
                                  ? 128
                                  : (remaining + one).bit_width() - 1;
        const int host_bits = std::min(align_bits, size_bits);
        const int prefix = 128 - host_bits;
        prefixes.push_back(IPv6Address(start.to_bytes()).to_string() + "/" +
                           std::to_string(prefix));

        if (host_bits == 128)
        {
            break;
        }
        const UInt128 next = start + (one << host_bits);
        if (next < start || next > end)
        {
            break;
        }
        start = next;
    }
    return prefixes;
}


enum class AddressFamily
{
    IPv4,
    IPv6
};

struct AddressSpan
{
    AddressFamily family{AddressFamily::IPv4};
    UInt128 start{};
    UInt128 end{};
};

UInt128 family_max(AddressFamily family)
{
    if (family == AddressFamily::IPv4)
    {
        return UInt128::from_u64(0xFFFFFFFFULL);
    }
    return {~0ULL, ~0ULL};
}

int family_width(AddressFamily family)
{
    return family == AddressFamily::IPv4 ? 32 : 128;
}

std::string format_span_address(AddressFamily family, const UInt128 &value)
{
    if (family == AddressFamily::IPv4)
    {
        return IPv4Address(static_cast<uint32_t>(value.lo)).to_string();
    }
    return IPv6Address(value.to_bytes()).to_string();
}

void ensure_same_family(const AddressSpan &lhs, const AddressSpan &rhs)
{
    if (lhs.family != rhs.family)
    {
        throw std::invalid_argument("Address family mismatch");
    }
}

bool spans_overlap(const AddressSpan &lhs, const AddressSpan &rhs)
{
    return lhs.start <= rhs.end && rhs.start <= lhs.end;
}

bool spans_adjacent(const AddressSpan &lhs, const AddressSpan &rhs)
{
    if (spans_overlap(lhs, rhs))
    {
        return false;
    }
    const auto max = family_max(lhs.family);
    if (lhs.end != max && lhs.end + UInt128::from_u64(1) == rhs.start)
    {
        return true;
    }
    if (rhs.end != max && rhs.end + UInt128::from_u64(1) == lhs.start)
    {
        return true;
    }
    return false;
}

PrefixRelation relate_spans(const AddressSpan &lhs, const AddressSpan &rhs)
{
    ensure_same_family(lhs, rhs);
    if (lhs.start == rhs.start && lhs.end == rhs.end)
    {
        return PrefixRelation::Equal;
    }
    if (lhs.start <= rhs.start && lhs.end >= rhs.end)
    {
        return PrefixRelation::Contains;
    }
    if (rhs.start <= lhs.start && rhs.end >= lhs.end)
    {
        return PrefixRelation::ContainedBy;
    }
    if (spans_overlap(lhs, rhs))
    {
        return PrefixRelation::Overlaps;
    }
    if (spans_adjacent(lhs, rhs))
    {
        return PrefixRelation::Adjacent;
    }
    return PrefixRelation::Disjoint;
}

AddressSpan span_from_analyzer(const IPAnalyzer &analyzer);

AddressSpan span_from_ipv4_prefix(uint32_t address, uint8_t cidr)
{
    const uint32_t network = cidr == 0 ? 0 : address & (0xFFFFFFFFU << (32 - cidr));
    const uint32_t broadcast = cidr == 0 ? 0xFFFFFFFFU : address | ~(0xFFFFFFFFU << (32 - cidr));
    return {AddressFamily::IPv4, UInt128::from_u64(network), UInt128::from_u64(broadcast)};
}

AddressSpan span_from_analyzer(const IPAnalyzer &analyzer)
{
    if (analyzer.get_ip()->is_ipv4())
    {
        const uint32_t network =
            std::dynamic_pointer_cast<IPv4Address>(analyzer.get_network())->to_uint32();
        const uint32_t broadcast =
            std::dynamic_pointer_cast<IPv4Address>(analyzer.get_broadcast())->to_uint32();
        return {AddressFamily::IPv4, UInt128::from_u64(network),
                UInt128::from_u64(broadcast)};
    }

    const auto ipv6 = std::dynamic_pointer_cast<IPv6Address>(analyzer.get_ip());
    if (ipv6->is_ipv4_mapped() && analyzer.get_cidr() >= 96)
    {
        const auto bytes = ipv6->to_bytes();
        const uint32_t embedded =
            (static_cast<uint32_t>(bytes[12]) << 24) |
            (static_cast<uint32_t>(bytes[13]) << 16) |
            (static_cast<uint32_t>(bytes[14]) << 8) |
            static_cast<uint32_t>(bytes[15]);
        return span_from_ipv4_prefix(embedded,
                                     static_cast<uint8_t>(analyzer.get_cidr() - 96));
    }

    const auto network =
        std::dynamic_pointer_cast<IPv6Address>(analyzer.get_network())->to_bytes();
    const auto broadcast =
        std::dynamic_pointer_cast<IPv6Address>(analyzer.get_broadcast())->to_bytes();
    return {AddressFamily::IPv6, UInt128::from_bytes(network),
            UInt128::from_bytes(broadcast)};
}

AddressSpan span_from_host(const IPAnalyzer &analyzer)
{
    if (analyzer.get_ip()->is_ipv4())
    {
        const uint32_t value =
            std::dynamic_pointer_cast<IPv4Address>(analyzer.get_ip())->to_uint32();
        return {AddressFamily::IPv4, UInt128::from_u64(value), UInt128::from_u64(value)};
    }

    const auto ipv6 = std::dynamic_pointer_cast<IPv6Address>(analyzer.get_ip());
    if (ipv6->is_ipv4_mapped())
    {
        const auto bytes = ipv6->to_bytes();
        const uint32_t embedded =
            (static_cast<uint32_t>(bytes[12]) << 24) |
            (static_cast<uint32_t>(bytes[13]) << 16) |
            (static_cast<uint32_t>(bytes[14]) << 8) |
            static_cast<uint32_t>(bytes[15]);
        return {AddressFamily::IPv4, UInt128::from_u64(embedded),
                UInt128::from_u64(embedded)};
    }

    const auto value = UInt128::from_bytes(ipv6->to_bytes());
    return {AddressFamily::IPv6, value, value};
}

AddressSpan span_from_range(std::string_view first, std::string_view last)
{
    const IPAnalyzer start(first);
    const IPAnalyzer stop(last);
    const auto lhs = span_from_host(start);
    const auto rhs = span_from_host(stop);
    ensure_same_family(lhs, rhs);
    if (lhs.start > rhs.start)
    {
        throw std::invalid_argument("Range start is after end");
    }
    return {lhs.family, lhs.start, rhs.end};
}

AddressSpan span_from_token(std::string_view token)
{
    if (const auto range = IPAnalyzer::parse_address_range(token))
    {
        return span_from_range(range->first, range->second);
    }
    return span_from_analyzer(IPAnalyzer(token));
}

std::vector<std::string> cidrs_from_span(const AddressSpan &span)
{
    return IPAnalyzer::cidrs_covering_range(format_span_address(span.family, span.start),
                                            format_span_address(span.family, span.end));
}

std::vector<AddressSpan> subtract_span(const AddressSpan &subject, const AddressSpan &hole)
{
    ensure_same_family(subject, hole);
    if (!spans_overlap(subject, hole))
    {
        return {subject};
    }

    std::vector<AddressSpan> remaining;
    if (subject.start < hole.start)
    {
        remaining.push_back(
            {subject.family, subject.start, hole.start - UInt128::from_u64(1)});
    }
    if (subject.end > hole.end)
    {
        remaining.push_back(
            {subject.family, hole.end + UInt128::from_u64(1), subject.end});
    }
    return remaining;
}

std::optional<AddressSpan> intersect_span(const AddressSpan &lhs, const AddressSpan &rhs)
{
    ensure_same_family(lhs, rhs);
    if (!spans_overlap(lhs, rhs))
    {
        return std::nullopt;
    }
    const UInt128 start = lhs.start > rhs.start ? lhs.start : rhs.start;
    const UInt128 end = lhs.end < rhs.end ? lhs.end : rhs.end;
    return AddressSpan{lhs.family, start, end};
}

std::vector<AddressSpan> merge_spans(std::vector<AddressSpan> spans)
{
    if (spans.empty())
    {
        return {};
    }
    for (size_t i = 1; i < spans.size(); ++i)
    {
        ensure_same_family(spans[0], spans[i]);
    }
    std::ranges::sort(spans, [](const AddressSpan &a, const AddressSpan &b) {
        return a.start < b.start;
    });

    std::vector<AddressSpan> merged;
    AddressSpan current = spans.front();
    for (const auto &next : spans | std::views::drop(1))
    {
        if (spans_overlap(current, next) || spans_adjacent(current, next))
        {
            if (next.end > current.end)
            {
                current.end = next.end;
            }
        }
        else
        {
            merged.push_back(current);
            current = next;
        }
    }
    merged.push_back(current);
    return merged;
}

std::vector<std::string> cidrs_from_spans(const std::vector<AddressSpan> &spans)
{
    std::vector<std::string> prefixes;
    for (const auto &span : spans)
    {
        auto part = cidrs_from_span(span);
        prefixes.insert(prefixes.end(), part.begin(), part.end());
    }
    return prefixes;
}

std::string add_offset_to_address(const IPAddress &address, uint64_t offset)
{
    if (address.is_ipv4())
    {
        const uint32_t value =
            dynamic_cast<const IPv4Address &>(address).to_uint32();
        if (offset > static_cast<uint64_t>(0xFFFFFFFFU - value))
        {
            throw std::invalid_argument("Host index is out of range");
        }
        return IPv4Address(value + static_cast<uint32_t>(offset)).to_string();
    }
    const auto bytes = dynamic_cast<const IPv6Address &>(address).to_bytes();
    const auto next = UInt128::from_bytes(bytes) + UInt128::from_u64(offset);
    if (next < UInt128::from_bytes(bytes) && offset != 0)
    {
        throw std::invalid_argument("Host index is out of range");
    }
    return IPv6Address(next.to_bytes()).to_string();
}

uint64_t resolve_index(int64_t index, uint64_t count)
{
    if (count == 0)
    {
        throw std::invalid_argument("Host index is out of range");
    }
    uint64_t ordinal = 0;
    if (index >= 0)
    {
        ordinal = static_cast<uint64_t>(index);
    }
    else if (index == -1)
    {
        ordinal = count - 1;
    }
    else
    {
        const uint64_t from_end = static_cast<uint64_t>(-index);
        if (from_end > count)
        {
            throw std::invalid_argument("Host index is out of range");
        }
        ordinal = count - from_end;
    }
    if (ordinal >= count)
    {
        throw std::invalid_argument("Host index is out of range");
    }
    return ordinal;
}

} // namespace

bool IPAnalyzer::contains(const IPAnalyzer &other) const
{
    const auto relation = relate_spans(span_from_analyzer(*this), span_from_analyzer(other));
    return relation == PrefixRelation::Equal || relation == PrefixRelation::Contains;
}

bool IPAnalyzer::overlaps(const IPAnalyzer &other) const
{
    const auto relation = relate_spans(span_from_analyzer(*this), span_from_analyzer(other));
    return relation == PrefixRelation::Equal || relation == PrefixRelation::Contains ||
           relation == PrefixRelation::ContainedBy || relation == PrefixRelation::Overlaps;
}

std::vector<std::string> IPAnalyzer::list_usable_hosts(uint64_t max_count) const
{
    const uint64_t count = get_num_hosts();
    if (count > max_count)
    {
        throw std::invalid_argument("Host list exceeds the configured safety limit");
    }

    const auto [first, last] = get_host_range();
    std::vector<std::string> hosts;
    hosts.reserve(static_cast<size_t>(count));

    if (ip_->is_ipv4())
    {
        uint32_t current =
            std::dynamic_pointer_cast<IPv4Address>(first)->to_uint32();
        const uint32_t stop =
            std::dynamic_pointer_cast<IPv4Address>(last)->to_uint32();
        while (true)
        {
            hosts.push_back(IPv4Address(current).to_string());
            if (current == stop)
            {
                break;
            }
            ++current;
        }
        return hosts;
    }

    auto current = std::dynamic_pointer_cast<IPv6Address>(first)->to_bytes();
    const auto stop = std::dynamic_pointer_cast<IPv6Address>(last)->to_bytes();
    while (true)
    {
        hosts.push_back(IPv6Address(current).to_string());
        if (current == stop)
        {
            break;
        }
        increment_ipv6(current);
    }
    return hosts;
}

std::optional<std::pair<std::string, std::string>>
IPAnalyzer::parse_address_range(std::string_view input)
{
    input = trim_view(input);
    if (input.empty())
    {
        return std::nullopt;
    }

    std::string_view first;
    std::string_view last;
    const auto spaced = input.find(" - ");
    if (spaced != std::string_view::npos)
    {
        first = input.substr(0, spaced);
        last = input.substr(spaced + 3);
    }
    else
    {
        const auto hyphen = input.find('-');
        if (hyphen == std::string_view::npos)
        {
            return std::nullopt;
        }
        first = input.substr(0, hyphen);
        last = input.substr(hyphen + 1);
    }

    first = trim_view(first);
    last = trim_view(last);
    if (first.empty() || last.empty())
    {
        return std::nullopt;
    }
    return std::pair<std::string, std::string>{std::string(first), std::string(last)};
}

std::vector<std::string> IPAnalyzer::cidrs_covering_range(std::string_view first,
                                                          std::string_view last)
{
    const IPAnalyzer start(first);
    const IPAnalyzer stop(last);
    if (start.get_ip()->is_ipv4() != stop.get_ip()->is_ipv4())
    {
        throw std::invalid_argument("Address family mismatch");
    }

    if (start.get_ip()->is_ipv4())
    {
        const uint32_t a =
            std::dynamic_pointer_cast<IPv4Address>(start.get_ip())->to_uint32();
        const uint32_t b =
            std::dynamic_pointer_cast<IPv4Address>(stop.get_ip())->to_uint32();
        if (a > b)
        {
            throw std::invalid_argument("Range start is after end");
        }
        return summarize_ipv4(a, b);
    }

    const auto a = UInt128::from_bytes(
        std::dynamic_pointer_cast<IPv6Address>(start.get_ip())->to_bytes());
    const auto b = UInt128::from_bytes(
        std::dynamic_pointer_cast<IPv6Address>(stop.get_ip())->to_bytes());
    if (a > b)
    {
        throw std::invalid_argument("Range start is after end");
    }
    return summarize_ipv6(a, b);
}

std::vector<std::string> IPAnalyzer::list_addresses_in_range(std::string_view first,
                                                             std::string_view last,
                                                             uint64_t max_count)
{
    const IPAnalyzer start(first);
    const IPAnalyzer stop(last);
    if (start.get_ip()->is_ipv4() != stop.get_ip()->is_ipv4())
    {
        throw std::invalid_argument("Address family mismatch");
    }

    if (start.get_ip()->is_ipv4())
    {
        const uint32_t a =
            std::dynamic_pointer_cast<IPv4Address>(start.get_ip())->to_uint32();
        const uint32_t b =
            std::dynamic_pointer_cast<IPv4Address>(stop.get_ip())->to_uint32();
        if (a > b)
        {
            throw std::invalid_argument("Range start is after end");
        }
        const uint64_t count = static_cast<uint64_t>(b) - a + 1;
        if (count > max_count)
        {
            throw std::invalid_argument("Host list exceeds the configured safety limit");
        }
        std::vector<std::string> hosts;
        hosts.reserve(static_cast<size_t>(count));
        uint32_t current = a;
        while (true)
        {
            hosts.push_back(IPv4Address(current).to_string());
            if (current == b)
            {
                break;
            }
            ++current;
        }
        return hosts;
    }

    const auto a = UInt128::from_bytes(
        std::dynamic_pointer_cast<IPv6Address>(start.get_ip())->to_bytes());
    const auto b = UInt128::from_bytes(
        std::dynamic_pointer_cast<IPv6Address>(stop.get_ip())->to_bytes());
    if (a > b)
    {
        throw std::invalid_argument("Range start is after end");
    }
    const UInt128 max{~0ULL, ~0ULL};
    const UInt128 one = UInt128::from_u64(1);
    if (a == UInt128{} && b == max)
    {
        throw std::invalid_argument("Host list exceeds the configured safety limit");
    }
    const UInt128 span = (b - a) + one;
    if (span.hi != 0 || span.lo > max_count)
    {
        throw std::invalid_argument("Host list exceeds the configured safety limit");
    }

    std::vector<std::string> hosts;
    hosts.reserve(static_cast<size_t>(span.lo));
    auto current = a.to_bytes();
    const auto stop_bytes = b.to_bytes();
    while (true)
    {
        hosts.push_back(IPv6Address(current).to_string());
        if (current == stop_bytes)
        {
            break;
        }
        increment_ipv6(current);
    }
    return hosts;
}

PrefixRelation IPAnalyzer::relate(const IPAnalyzer &other) const
{
    return relate_spans(span_from_analyzer(*this), span_from_analyzer(other));
}

bool IPAnalyzer::is_adjacent(const IPAnalyzer &other) const
{
    return relate(other) == PrefixRelation::Adjacent;
}

std::string IPAnalyzer::next_prefix() const
{
    const bool ipv4 = ip_->is_ipv4();
    const int width = ipv4 ? 32 : 128;
    if (cidr_ == 0)
    {
        throw std::invalid_argument("No next prefix in the address space");
    }
    const int host_bits = width - cidr_;
    const UInt128 block = UInt128::from_u64(1) << host_bits;
    UInt128 network;
    if (ipv4)
    {
        network = UInt128::from_u64(
            std::dynamic_pointer_cast<IPv4Address>(get_network())->to_uint32());
    }
    else
    {
        network = UInt128::from_bytes(
            std::dynamic_pointer_cast<IPv6Address>(get_network())->to_bytes());
    }
    const UInt128 next = network + block;
    if (next < network || (ipv4 && next > UInt128::from_u64(0xFFFFFFFFULL)))
    {
        throw std::invalid_argument("No next prefix in the address space");
    }
    return format_span_address(ipv4 ? AddressFamily::IPv4 : AddressFamily::IPv6, next) +
           "/" + std::to_string(cidr_);
}

std::string IPAnalyzer::prev_prefix() const
{
    const bool ipv4 = ip_->is_ipv4();
    const int width = ipv4 ? 32 : 128;
    if (cidr_ == 0)
    {
        throw std::invalid_argument("No previous prefix in the address space");
    }
    const int host_bits = width - cidr_;
    const UInt128 block = UInt128::from_u64(1) << host_bits;
    UInt128 network;
    if (ipv4)
    {
        network = UInt128::from_u64(
            std::dynamic_pointer_cast<IPv4Address>(get_network())->to_uint32());
    }
    else
    {
        network = UInt128::from_bytes(
            std::dynamic_pointer_cast<IPv6Address>(get_network())->to_bytes());
    }
    if (network < block)
    {
        throw std::invalid_argument("No previous prefix in the address space");
    }
    return format_span_address(ipv4 ? AddressFamily::IPv4 : AddressFamily::IPv6,
                               network - block) +
           "/" + std::to_string(cidr_);
}

std::vector<std::string> IPAnalyzer::exclude(const IPAnalyzer &other) const
{
    return cidrs_from_spans(
        subtract_span(span_from_analyzer(*this), span_from_analyzer(other)));
}

std::vector<std::string> IPAnalyzer::intersect(const IPAnalyzer &other) const
{
    const auto common = intersect_span(span_from_analyzer(*this), span_from_analyzer(other));
    if (!common)
    {
        return {};
    }
    return cidrs_from_span(*common);
}

std::vector<std::string> IPAnalyzer::split(uint8_t child_prefix) const
{
    const bool ipv4 = ip_->is_ipv4();
    const int width = ipv4 ? 32 : 128;
    if (child_prefix <= cidr_ || child_prefix > width)
    {
        throw std::invalid_argument("Invalid split prefix length");
    }
    const int count_bits = child_prefix - cidr_;
    if (count_bits > 16)
    {
        throw std::invalid_argument("Split produces too many prefixes");
    }
    const uint32_t count = 1U << count_bits;
    const int step_bits = width - child_prefix;
    UInt128 network;
    if (ipv4)
    {
        network = UInt128::from_u64(
            std::dynamic_pointer_cast<IPv4Address>(get_network())->to_uint32());
    }
    else
    {
        network = UInt128::from_bytes(
            std::dynamic_pointer_cast<IPv6Address>(get_network())->to_bytes());
    }
    const UInt128 step = UInt128::from_u64(1) << step_bits;
    std::vector<std::string> prefixes;
    prefixes.reserve(count);
    UInt128 current = network;
    for (uint32_t i = 0; i < count; ++i)
    {
        prefixes.push_back(
            format_span_address(ipv4 ? AddressFamily::IPv4 : AddressFamily::IPv6,
                                current) +
            "/" + std::to_string(child_prefix));
        current = current + step;
    }
    return prefixes;
}

std::string IPAnalyzer::nth_address(int64_t index) const
{
    const uint64_t count = get_num_hosts();
    const uint64_t ordinal = resolve_index(index, count);
    const auto [first, last] = get_host_range();
    (void)last;
    return add_offset_to_address(*first, ordinal);
}

std::vector<std::string> IPAnalyzer::aggregate(std::span<const std::string> inputs)
{
    std::vector<AddressSpan> spans;
    spans.reserve(inputs.size());
    for (const auto &input : inputs)
    {
        spans.push_back(span_from_token(input));
    }
    return cidrs_from_spans(merge_spans(std::move(spans)));
}

std::vector<std::string> IPAnalyzer::exclude_from_range(std::string_view first,
                                                       std::string_view last,
                                                       std::string_view hole)
{
    return cidrs_from_spans(
        subtract_span(span_from_range(first, last), span_from_token(hole)));
}

std::vector<std::string> IPAnalyzer::intersect_with_range(std::string_view first,
                                                         std::string_view last,
                                                         std::string_view other)
{
    const auto common =
        intersect_span(span_from_range(first, last), span_from_token(other));
    if (!common)
    {
        return {};
    }
    return cidrs_from_span(*common);
}

std::string IPAnalyzer::nth_address_in_range(std::string_view first, std::string_view last,
                                             int64_t index)
{
    const auto span = span_from_range(first, last);
    UInt128 count_span = (span.end - span.start) + UInt128::from_u64(1);
    if (count_span.hi != 0 || count_span.lo == 0)
    {
        throw std::invalid_argument("Host index is out of range");
    }
    const uint64_t ordinal = resolve_index(index, count_span.lo);
    const auto value = span.start + UInt128::from_u64(ordinal);
    return format_span_address(span.family, value);
}

PrefixRelation IPAnalyzer::relate_range(std::string_view first, std::string_view last,
                                        std::string_view other)
{
    return relate_spans(span_from_range(first, last), span_from_token(other));
}
