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
#include <algorithm>
#include <regex>
#include <vector>
#include <iomanip>
#include <limits>
#include <charconv>
#include <system_error>

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
        for (size_t index = 0; index < 10; ++index)
        {
            if (bytes_[index] != 0)
            {
                throw std::invalid_argument("Only IPv4-mapped IPv6 addresses are supported");
            }
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

        for (int i = 0; i < missing_segments; ++i) {
            segments.emplace_back();
        }
        segments.insert(segments.end(), after_segments.begin(), after_segments.end());
    } else {
        segments = split_segments(address);
        if (segments.size() != 8) {
            throw std::invalid_argument("Invalid IPv6 address format: incorrect segment count");
        }
    }

    std::string result;
    result.reserve(39);
    for (size_t i = 0; i < segments.size(); ++i) {
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
    for (size_t index = 0; index < 10; ++index)
    {
        if (bytes_[index] != 0)
        {
            return false;
        }
    }
    return bytes_[10] == 0xFF && bytes_[11] == 0xFF;
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
    for (size_t i = 0; i < 8; ++i)
    {
        groups[i] = static_cast<uint16_t>((bytes_[i * 2] << 8) | bytes_[i * 2 + 1]);
    }

    size_t best_start = 0;
    size_t best_len = 0;
    size_t current_start = 0;
    size_t current_len = 0;
    for (size_t i = 0; i < groups.size(); ++i)
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
    for (size_t i = 0; i < groups.size(); ++i)
    {
        if (best_len > 0 && i == best_start)
        {
            oss << "::";
            i += best_len - 1;
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

        for (int i = fullBytes + (remainingBits > 0 ? 1 : 0); i < 16; ++i)
        {
            network_bytes[i] = 0;
        }

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

        for (int i = fullBytes + (remainingBits > 0 ? 1 : 0); i < 16; ++i)
        {
            ip_bytes[i] = 0xFF;
        }

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
        for (int i = fullBytes + (remainingBits > 0 ? 1 : 0); i < 16; ++i)
        {
            last_bytes[i] = 0xFF;
        }

        if (cidr_ < 127)
        {
            for (int i = 15; i >= 0; --i)
            {
                if (++network_bytes[i] != 0)
                    break;
            }

            for (int i = 15; i >= 0; --i)
            {
                if (--last_bytes[i] != 0xFF)
                    break;
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
    for (int i = 3; i >= 0; --i)
    {
        octets_[i] = static_cast<uint8_t>(address & 0xFF);
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
    for (int i = 0; i < 4; ++i)
    {
        oss << std::bitset<8>(octets_[i]).to_string();
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
