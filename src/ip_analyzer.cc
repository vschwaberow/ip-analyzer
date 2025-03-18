// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: src/ip_analyzer.cc
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#include "ip_analyzer.hh"
#include <stdexcept>
#include <sstream>
#include <bitset>
#include <algorithm>
#include <regex>
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
    uint32_t mask = 0xFFFFFFFF << (32 - cidr);
    return ip_int & mask;
}

uint32_t IPAnalyzer::calculate_ipv4_broadcast(uint32_t ip_int, uint8_t cidr)
{
    if (cidr == 0)
    {
        return 0xFFFFFFFF;
    }
    uint32_t mask = 0xFFFFFFFF << (32 - cidr);
    return ip_int | ~mask;
}

IPv6Address::IPv6Address(std::string_view address)
{
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

    int segment_count = 0;
    int colon_count = 0;
    
    for (char c : address) {
        if (c == ':') {
            colon_count++;
        }
    }
    
    if (has_double_colon) {
        segment_count = colon_count - 1;
        if (address.front() == ':') segment_count--;
        if (address.back() == ':') segment_count--;
    } else {
        segment_count = colon_count + 1;
    }
    
    int missing_segments = 8 - segment_count;
    if (missing_segments < 0) {
        throw std::invalid_argument("Invalid IPv6 address format: too many segments");
    }
    
    std::string result;
    result.reserve(39);
    
    if (has_double_colon) {
        std::string_view before = address.substr(0, double_colon_pos);
        
        std::string_view after = address.substr(
            std::min(address.size(), double_colon_pos + 2));
        
        if (!before.empty()) {
            expand_ipv6_segments(before, result);
            result.push_back(':');
        }
        
        for (int i = 0; i < missing_segments; ++i) {
            result.append("0000:");
        }
        
        if (!after.empty()) {
            if (result.back() == ':' && after.front() == ':') {
                expand_ipv6_segments(after.substr(1), result);
            } else {
                expand_ipv6_segments(after, result);
            }
        }
    } else {
        expand_ipv6_segments(address, result);
    }
    
    int final_segments = 1;
    for (char c : result) {
        if (c == ':') final_segments++;
    }
    
    while (final_segments < 8) {
        result.append(":0000");
        final_segments++;
    }
    
    return result;
}

void IPv6Address::expand_ipv6_segments(std::string_view segments, std::string& result) {
    size_t start = 0;
    size_t end = segments.find(':', start);
    
    while (start != std::string_view::npos) {
        std::string_view segment = (end != std::string_view::npos) ? 
            segments.substr(start, end - start) : segments.substr(start);
        
        if (!segment.empty()) {
            int value = 0;
            for (char c : segment) {
                value = value * 16 + hex_char_to_int(c);
            }
            
            char hex_buffer[5];
            std::snprintf(hex_buffer, sizeof(hex_buffer), "%04x", value);
            result.append(hex_buffer);
        } else {
            result.append("0000");
        }
        
        if (end != std::string_view::npos) {
            result.push_back(':');
            start = end + 1;
            end = segments.find(':', start);
        } else {
            break;
        }
    }
}

constexpr int IPv6Address::hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

IPv6Address::IPv6Address(const std::array<uint8_t, 16> &bytes) : bytes_(bytes) {}

std::string IPv6Address::to_string() const
{
    std::ostringstream oss;
    for (size_t i = 0; i < 16; i += 2)
    {
        if (i > 0)
            oss << ':';
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes_[i]);
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes_[i + 1]);
    }
    return oss.str();
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
    return (bytes_[0] == 0xFD || bytes_[0] == 0xFC);
}

std::array<uint8_t, 16> IPv6Address::to_bytes() const
{
    return bytes_;
}

IPAnalyzer::IPAnalyzer(std::string_view ip_cidr)
{
    auto slash_pos = ip_cidr.find('/');
    std::string_view ip_str;

    if (slash_pos == std::string_view::npos)
    {
        ip_str = ip_cidr;
        cidr_ = ip_cidr.contains(':') ? 128 : 32;
    }
    else
    {
        ip_str = ip_cidr.substr(0, slash_pos);
        const std::string_view cidr_str = ip_cidr.substr(slash_pos + 1);
        uint16_t cidr_value{};
        const auto result = std::from_chars(cidr_str.data(), cidr_str.data() + cidr_str.size(), cidr_value);
        
        if (result.ec != std::errc{})
        {
            throw std::invalid_argument("Invalid CIDR format");
        }
        cidr_ = static_cast<uint8_t>(cidr_value);
    }

    if (ip_str.contains(':'))
    {
        ip_ = std::make_shared<IPv6Address>(ip_str);
        if (cidr_ > 128)
            throw std::invalid_argument("Invalid IPv6 CIDR value");
    }
    else
    {
        ip_ = std::make_shared<IPv4Address>(ip_str);
        if (cidr_ > 32)
            throw std::invalid_argument("Invalid IPv4 CIDR value");
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
        uint32_t mask = 0xFFFFFFFF << (32 - cidr_);
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

        for (int i = fullBytes; i < 16; ++i)
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
        uint32_t mask = 0xFFFFFFFF << (32 - cidr_);
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
        auto ipv6 = std::dynamic_pointer_cast<IPv6Address>(ip_);
        std::array<uint8_t, 16> network_bytes = ipv6->to_bytes();
        std::array<uint8_t, 16> last_bytes = network_bytes;

        int fullBytes = cidr_ / 8;
        int remainingBits = cidr_ % 8;

        for (int i = fullBytes; i < 16; ++i)
        {
            last_bytes[i] = 0xFF;
        }
        if (remainingBits > 0)
        {
            last_bytes[fullBytes] |= static_cast<uint8_t>(0xFF >> remainingBits);
        }

        if (cidr_ < 128)
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

        if (cidr_ <= 64)
        {
            return std::numeric_limits<uint64_t>::max();
        }
        else
        {
            return 1ULL << (128 - cidr_);
        }
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
    std::istringstream iss(address.data());
    std::string octet;
    int i = 0;
    while (std::getline(iss, octet, '.'))
    {
        if (i >= 4)
        {
            throw std::invalid_argument("Invalid IPv4 address format");
        }
        int value = std::stoi(octet);
        if (value < 0 || value > 255)
        {
            throw std::invalid_argument("Invalid octet value");
        }
        octets_[i++] = static_cast<uint8_t>(value);
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