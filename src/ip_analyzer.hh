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
    [[nodiscard]] virtual std::string to_string() const = 0;
    [[nodiscard]] virtual std::string to_binary_string() const = 0;
    [[nodiscard]] virtual bool is_private() const = 0;
    [[nodiscard]] virtual bool is_ipv4() const = 0;
    [[nodiscard]] virtual bool is_ipv6() const = 0;
};

class IPv4Address : public IPAddress
{
public:
    explicit IPv4Address(std::string_view address);
    explicit IPv4Address(uint32_t address);

    [[nodiscard]] std::string to_string() const override;
    [[nodiscard]] std::string to_binary_string() const override;
    [[nodiscard]] bool is_private() const override;
    [[nodiscard]] bool is_ipv4() const override { return true; }
    [[nodiscard]] bool is_ipv6() const override { return false; }

    [[nodiscard]] uint32_t to_uint32() const;

private:
    std::array<uint8_t, 4> octets_{};
};

class IPv6Address : public IPAddress
{
public:
    explicit IPv6Address(std::string_view address);
    explicit IPv6Address(const std::array<uint8_t, 16>& bytes);

    [[nodiscard]] std::string to_string() const override;
    [[nodiscard]] std::string to_binary_string() const override;
    [[nodiscard]] bool is_private() const override;
    [[nodiscard]] bool is_ipv4() const override { return false; }
    [[nodiscard]] bool is_ipv6() const override { return true; }
    [[nodiscard]] std::array<uint8_t, 16> to_bytes() const;

private:
    std::array<uint8_t, 16> bytes_{};
    static std::string convert_ipv4_mapped(std::string_view address);
    static std::string expand_ipv6_address(std::string_view address);
    static constexpr int hex_char_to_int(char c);
};

class IPAnalyzer
{
public:
    explicit IPAnalyzer(std::string_view ip_cidr);

    [[nodiscard]] std::shared_ptr<IPAddress> get_ip() const;
    [[nodiscard]] std::shared_ptr<IPAddress> get_network() const;
    [[nodiscard]] std::shared_ptr<IPAddress> get_netmask() const;
    [[nodiscard]] std::shared_ptr<IPAddress> get_broadcast() const;
    [[nodiscard]] std::pair<std::shared_ptr<IPAddress>, std::shared_ptr<IPAddress>> get_host_range() const;
    [[nodiscard]] uint64_t get_num_hosts() const;
    [[nodiscard]] bool is_private() const;
    [[nodiscard]] uint8_t get_cidr() const;

private:
    std::shared_ptr<IPAddress> ip_;
    uint8_t cidr_{};

    static uint32_t calculate_ipv4_network(uint32_t ip_int, uint8_t cidr);
    static uint32_t calculate_ipv4_broadcast(uint32_t ip_int, uint8_t cidr);
};
