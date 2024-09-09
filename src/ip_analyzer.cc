#include "ip_analyzer.hh"
#include <bitset>
#include <stdexcept>
#include <sstream>
#include <algorithm>

IPv4Address::IPv4Address(std::string_view address)
{
    std::istringstream iss(address.data());
    std::string octet;
    size_t i = 0;
    while (std::getline(iss, octet, '.'))
    {
        if (i >= 4)
            throw std::invalid_argument("Invalid IP address format: too many octets");
        int value = std::stoi(octet);
        if (value < 0 || value > 255)
            throw std::invalid_argument("Invalid IP address octet value");
        octets_[i++] = static_cast<uint8_t>(value);
    }
    if (i != 4)
        throw std::invalid_argument("Invalid IP address format: not enough octets");
}

IPv4Address::IPv4Address(uint32_t address)
{
    octets_[0] = static_cast<uint8_t>((address >> 24) & 0xFF);
    octets_[1] = static_cast<uint8_t>((address >> 16) & 0xFF);
    octets_[2] = static_cast<uint8_t>((address >> 8) & 0xFF);
    octets_[3] = static_cast<uint8_t>(address & 0xFF);
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
    for (auto octet : octets_)
    {
        oss << std::bitset<8>(octet).to_string();
    }
    return oss.str();
}

uint32_t IPv4Address::to_uint32() const
{
    return (octets_[0] << 24) | (octets_[1] << 16) | (octets_[2] << 8) | octets_[3];
}

IPAnalyzer::IPAnalyzer(std::string_view ip_cidr) : ip_(ip_cidr.substr(0, ip_cidr.find('/')))
{
    auto slash_pos = ip_cidr.find('/');
    if (slash_pos == std::string_view::npos)
        throw std::invalid_argument("Invalid IP/CIDR format");
    cidr_ = static_cast<uint8_t>(std::stoi(std::string(ip_cidr.substr(slash_pos + 1))));
    if (cidr_ > 32)
        throw std::invalid_argument("Invalid CIDR value");
}

IPv4Address IPAnalyzer::get_ip() const { return ip_; }

IPv4Address IPAnalyzer::get_network() const
{
    if (cidr_ == 0)
        return IPv4Address("0.0.0.0");
    uint32_t ip = ip_.to_uint32();
    uint32_t mask = (cidr_ == 32) ? 0xFFFFFFFF : ~(0xFFFFFFFF >> cidr_);
    return IPv4Address(ip & mask);
}

IPv4Address IPAnalyzer::get_netmask() const
{
    if (cidr_ == 32)
        return IPv4Address("255.255.255.255");
    uint32_t mask = (cidr_ == 0) ? 0 : (~0U << (32 - cidr_));
    return IPv4Address(mask);
}

IPv4Address IPAnalyzer::get_broadcast() const
{
    if (cidr_ == 32)
        return ip_;
    if (cidr_ == 0)
        return IPv4Address("255.255.255.255");
    uint32_t ip_int = ip_.to_uint32();
    uint32_t mask = (~0U << (32 - cidr_));
    return IPv4Address(ip_int | ~mask);
}

std::pair<IPv4Address, IPv4Address> IPAnalyzer::get_host_range() const
{
    if (cidr_ == 32)
        return {ip_, ip_};
    uint32_t network_int = get_network().to_uint32();
    uint32_t broadcast_int = get_broadcast().to_uint32();
    return {IPv4Address(network_int + 1), IPv4Address(broadcast_int - 1)};
}

uint32_t IPAnalyzer::get_num_hosts() const
{
    if (cidr_ == 32)
        return 1;
    if (cidr_ == 31)
        return 2;
    if (cidr_ == 0)
        return 0xFFFFFFFE;
    return (1ULL << (32 - cidr_)) - 2;
}

bool IPAnalyzer::is_private() const
{
    uint32_t ip = ip_.to_uint32();
    return (ip >= 0x0A000000 && ip <= 0x0AFFFFFF) ||
           (ip >= 0xAC100000 && ip <= 0xAC1FFFFF) ||
           (ip >= 0xC0A80000 && ip <= 0xC0A8FFFF);
}

uint8_t IPAnalyzer::get_cidr() const { return cidr_; }