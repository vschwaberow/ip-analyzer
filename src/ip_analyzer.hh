// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: src/ip_analyzer.hh
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <memory>

class IPAddress
{
public:
    virtual ~IPAddress() = default;
    virtual std::string to_string() const = 0;
    virtual std::string to_binary_string() const = 0;
    virtual bool is_private() const = 0;
    virtual bool is_ipv4() const = 0;
    virtual bool is_ipv6() const = 0;
};

class IPv4Address : public IPAddress
{
public:
    IPv4Address(std::string_view address);
    explicit IPv4Address(uint32_t address);

    std::string to_string() const override;
    std::string to_binary_string() const override;
    bool is_private() const override;
    bool is_ipv4() const override { return true; }
    bool is_ipv6() const override { return false; }

    uint32_t to_uint32() const;

private:
    std::array<uint8_t, 4> octets_;
};

class IPv6Address : public IPAddress
{
public:
    explicit IPv6Address(std::string_view address);
    explicit IPv6Address(const std::array<uint8_t, 16>& bytes);

    std::string to_string() const override;
    std::string to_binary_string() const override;
    bool is_private() const override;
    bool is_ipv4() const override { return false; }
    bool is_ipv6() const override { return true; }
    std::array<uint8_t, 16> to_bytes() const;

private:
    std::array<uint8_t, 16> bytes_;
    static std::string convert_ipv4_mapped(std::string_view address);
    static std::string expand_ipv6_address(std::string_view address);
    static void expand_ipv6_segments(std::string_view segments, std::string& result);
    static constexpr int hex_char_to_int(char c);
};

class IPAnalyzer
{
public:
    IPAnalyzer(std::string_view ip_cidr);

    std::shared_ptr<IPAddress> get_ip() const;
    std::shared_ptr<IPAddress> get_network() const;
    std::shared_ptr<IPAddress> get_netmask() const;
    std::shared_ptr<IPAddress> get_broadcast() const;
    std::pair<std::shared_ptr<IPAddress>, std::shared_ptr<IPAddress>> get_host_range() const;
    uint64_t get_num_hosts() const;
    bool is_private() const;
    uint8_t get_cidr() const;

private:
    std::shared_ptr<IPAddress> ip_;
    uint8_t cidr_;

    static uint32_t calculate_ipv4_network(uint32_t ip_int, uint8_t cidr);
    static uint32_t calculate_ipv4_broadcast(uint32_t ip_int, uint8_t cidr);
};
