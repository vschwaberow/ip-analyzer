#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

class IPv4Address
{
public:
    explicit IPv4Address(std::string_view address);
    explicit IPv4Address(uint32_t address); // Add this constructor
    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] std::string to_binary_string() const;
    [[nodiscard]] uint32_t to_uint32() const;

private:
    std::array<uint8_t, 4> octets_;
};

class IPAnalyzer
{
public:
    explicit IPAnalyzer(std::string_view ip_cidr);

    [[nodiscard]] IPv4Address get_ip() const;
    [[nodiscard]] IPv4Address get_network() const;
    [[nodiscard]] IPv4Address get_netmask() const;
    [[nodiscard]] IPv4Address get_broadcast() const;
    [[nodiscard]] std::pair<IPv4Address, IPv4Address> get_host_range() const;
    [[nodiscard]] uint32_t get_num_hosts() const;
    [[nodiscard]] bool is_private() const;
    [[nodiscard]] uint8_t get_cidr() const;

private:
    IPv4Address ip_;
    uint8_t cidr_;
};