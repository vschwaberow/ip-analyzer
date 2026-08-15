// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: src/ip_analyzer.hh
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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
    [[nodiscard]] bool is_ipv4_mapped() const;

private:
    std::array<uint8_t, 16> bytes_{};
    static std::string convert_ipv4_mapped(std::string_view address);
    static std::string expand_ipv6_address(std::string_view address);
    static constexpr int hex_char_to_int(char c);
};

enum class PrefixRelation
{
    Equal,
    Contains,
    ContainedBy,
    Overlaps,
    Adjacent,
    Disjoint
};

[[nodiscard]] constexpr std::string_view prefix_relation_name(PrefixRelation relation) noexcept
{
    switch (relation)
    {
    case PrefixRelation::Equal:
        return "equal";
    case PrefixRelation::Contains:
        return "contains";
    case PrefixRelation::ContainedBy:
        return "contained";
    case PrefixRelation::Overlaps:
        return "overlaps";
    case PrefixRelation::Adjacent:
        return "adjacent";
    case PrefixRelation::Disjoint:
        return "disjoint";
    }
    return "disjoint";
}

class IPAnalyzer
{
public:
    static constexpr uint64_t kDefaultMaxListedHosts = 1ULL << 20;

    explicit IPAnalyzer(std::string_view ip_cidr);

    [[nodiscard]] std::shared_ptr<IPAddress> get_ip() const;
    [[nodiscard]] std::shared_ptr<IPAddress> get_network() const;
    [[nodiscard]] std::shared_ptr<IPAddress> get_netmask() const;
    [[nodiscard]] std::shared_ptr<IPAddress> get_broadcast() const;
    [[nodiscard]] std::pair<std::shared_ptr<IPAddress>, std::shared_ptr<IPAddress>> get_host_range() const;
    [[nodiscard]] uint64_t get_num_hosts() const;
    [[nodiscard]] bool is_private() const;
    [[nodiscard]] uint8_t get_cidr() const;

    [[nodiscard]] bool contains(const IPAnalyzer& other) const;
    [[nodiscard]] bool overlaps(const IPAnalyzer& other) const;
    [[nodiscard]] PrefixRelation relate(const IPAnalyzer& other) const;
    [[nodiscard]] bool is_adjacent(const IPAnalyzer& other) const;
    [[nodiscard]] std::string next_prefix() const;
    [[nodiscard]] std::string prev_prefix() const;
    [[nodiscard]] std::vector<std::string> exclude(const IPAnalyzer& other) const;
    [[nodiscard]] std::vector<std::string> intersect(const IPAnalyzer& other) const;
    [[nodiscard]] std::vector<std::string> split(uint8_t child_prefix) const;
    [[nodiscard]] std::string nth_address(int64_t index) const;
    [[nodiscard]] std::vector<std::string> list_usable_hosts(
        uint64_t max_count = kDefaultMaxListedHosts) const;

    [[nodiscard]] static std::optional<std::pair<std::string, std::string>>
    parse_address_range(std::string_view input);
    [[nodiscard]] static std::vector<std::string>
    cidrs_covering_range(std::string_view first, std::string_view last);
    [[nodiscard]] static std::vector<std::string>
    list_addresses_in_range(std::string_view first, std::string_view last,
                            uint64_t max_count = kDefaultMaxListedHosts);
    [[nodiscard]] static std::vector<std::string>
    aggregate(std::span<const std::string> inputs);
    [[nodiscard]] static std::vector<std::string>
    exclude_from_range(std::string_view first, std::string_view last,
                       std::string_view hole);
    [[nodiscard]] static std::vector<std::string>
    intersect_with_range(std::string_view first, std::string_view last,
                         std::string_view other);
    [[nodiscard]] static std::string
    nth_address_in_range(std::string_view first, std::string_view last,
                         int64_t index);
    [[nodiscard]] static PrefixRelation
    relate_range(std::string_view first, std::string_view last,
                 std::string_view other);

private:
    std::shared_ptr<IPAddress> ip_;
    uint8_t cidr_{};

    static uint32_t calculate_ipv4_network(uint32_t ip_int, uint8_t cidr);
    static uint32_t calculate_ipv4_broadcast(uint32_t ip_int, uint8_t cidr);
};
