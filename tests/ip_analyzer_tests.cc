// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: src/tests/ip_analyzer_tests.cc
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>
#include "ip_analyzer.hh"
#include <limits>

TEST_CASE("IPv4Address construction and methods", "[ipv4address]") {
    IPv4Address ip("192.168.0.1");

    REQUIRE(ip.to_string() == "192.168.0.1");
    REQUIRE(ip.to_binary_string() == "11000000101010000000000000000001");
    REQUIRE(ip.to_uint32() == 3232235521);
}

TEST_CASE("IPAnalyzer functionality", "[ipanalyzer]") {
    IPAnalyzer analyzer("192.168.0.1/24");

    REQUIRE(analyzer.get_ip()->to_string() == "192.168.0.1");
    REQUIRE(analyzer.get_network()->to_string() == "192.168.0.0");
    REQUIRE(analyzer.get_netmask()->to_string() == "255.255.255.0");
    REQUIRE(analyzer.get_broadcast()->to_string() == "192.168.0.255");

    auto [first, last] = analyzer.get_host_range();
    REQUIRE(first->to_string() == "192.168.0.1");
    REQUIRE(last->to_string() == "192.168.0.254");

    REQUIRE(analyzer.get_num_hosts() == 254);
    REQUIRE(analyzer.is_private() == true);
    REQUIRE(analyzer.get_cidr() == 24);
}

TEST_CASE("Edge cases for IPv4Address", "[ipv4address]") {
    SECTION("Minimum IP address") {
        IPv4Address min_ip("0.0.0.0");
        REQUIRE(min_ip.to_string() == "0.0.0.0");
        REQUIRE(min_ip.to_uint32() == 0);
    }

    SECTION("Maximum IP address") {
        IPv4Address max_ip("255.255.255.255");
        REQUIRE(max_ip.to_string() == "255.255.255.255");
        REQUIRE(max_ip.to_uint32() == 4294967295);
    }

    SECTION("Invalid IP address formats") {
        REQUIRE_THROWS_AS(IPv4Address("256.0.0.1"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPv4Address("192.168.0"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPv4Address("192.168.0.1.2"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPv4Address("192.168.0.a"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPv4Address("192.168.0.1/24"), std::invalid_argument);
    }
}

TEST_CASE("Edge cases for IPAnalyzer", "[ipanalyzer]") {
    SECTION("Minimum CIDR") {
        IPAnalyzer analyzer("192.168.0.1/0");
        REQUIRE(analyzer.get_network()->to_string() == "0.0.0.0");
        REQUIRE(analyzer.get_broadcast()->to_string() == "255.255.255.255");
        REQUIRE(analyzer.get_netmask()->to_string() == "0.0.0.0");
        auto [first, last] = analyzer.get_host_range();
        REQUIRE(first->to_string() == "0.0.0.1");
        REQUIRE(last->to_string() == "255.255.255.254");
        REQUIRE(analyzer.get_num_hosts() == 4294967294);
    }

    SECTION("CIDR /31") {
        IPAnalyzer analyzer("192.168.0.1/31");
        REQUIRE(analyzer.get_network()->to_string() == "192.168.0.0");
        REQUIRE(analyzer.get_broadcast()->to_string() == "192.168.0.1");
        auto [first, last] = analyzer.get_host_range();
        REQUIRE(first->to_string() == "192.168.0.0");
        REQUIRE(last->to_string() == "192.168.0.1");
        REQUIRE(analyzer.get_num_hosts() == 2);
    }

    SECTION("Maximum CIDR") {
        IPAnalyzer analyzer("192.168.0.1/32");
        REQUIRE(analyzer.get_network()->to_string() == "192.168.0.1");
        REQUIRE(analyzer.get_broadcast()->to_string() == "192.168.0.1");
        REQUIRE(analyzer.get_num_hosts() == 1);

        auto [first, last] = analyzer.get_host_range();
        REQUIRE(first->to_string() == "192.168.0.1");
        REQUIRE(last->to_string() == "192.168.0.1");
    }

    SECTION("Invalid CIDR values") {
        REQUIRE_THROWS_AS(IPAnalyzer("192.168.0.1/33"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPAnalyzer("192.168.0.1/-1"), std::invalid_argument);
    }

    SECTION("IPv4 netmask notation") {
        IPAnalyzer analyzer("192.168.0.1/255.255.255.0");
        REQUIRE(analyzer.get_cidr() == 24);
        REQUIRE(analyzer.get_netmask()->to_string() == "255.255.255.0");
        REQUIRE_THROWS_AS(IPAnalyzer("192.168.0.1/255.0.255.0"), std::invalid_argument);
    }

    SECTION("Private IP ranges") {
        REQUIRE(IPAnalyzer("10.0.0.1/24").is_private() == true);
        REQUIRE(IPAnalyzer("172.16.0.1/24").is_private() == true);
        REQUIRE(IPAnalyzer("192.168.0.1/24").is_private() == true);
        REQUIRE(IPAnalyzer("8.8.8.8/24").is_private() == false);
    }

    SECTION("Class A, B, C network boundaries") {
        REQUIRE(IPAnalyzer("127.255.255.255/8").get_network()->to_string() == "127.0.0.0");
    }
}

TEST_CASE("IPv6Address construction and methods", "[ipv6address]") {
    IPv6Address ip("2001:0db8:0000:0000:0000:0000:0000:0001");
    REQUIRE(ip.to_string() == "2001:db8::1");

    std::string binary = ip.to_binary_string();
    REQUIRE(binary.length() == 128);

    REQUIRE(ip.is_private() == false);
}

TEST_CASE("IPv6Address compressed notation expansion", "[ipv6address]") {
    REQUIRE(IPv6Address("::").to_string() == "::");
    REQUIRE(IPv6Address("::1").to_string() == "::1");
    REQUIRE(IPv6Address("2001:db8::1").to_string() == "2001:db8::1");
    REQUIRE(IPv6Address("2001:0db8:0000:0000:0000:0000:0000:0000").to_string() == "2001:db8::");
    REQUIRE(IPv6Address("fe80:0000:0000:0000:0202:b3ff:fe1e:8329").to_string() == "fe80::202:b3ff:fe1e:8329");
    REQUIRE_THROWS_AS(IPv6Address("2001:db8:00000::1"), std::invalid_argument);
}

TEST_CASE("IPv6Address IPv4-mapped parsing", "[ipv6address]") {
    REQUIRE(IPv6Address("::ffff:192.0.2.128").to_string() == "::ffff:192.0.2.128");
    REQUIRE(IPv6Address("0:0:0:0:0:ffff:192.0.2.128").to_string() == "::ffff:192.0.2.128");
    REQUIRE_THROWS_AS(IPv6Address("2001:db8::192.0.2.1"), std::invalid_argument);
}

TEST_CASE("IPAnalyzer IPv6 functionality", "[ipanalyzer][ipv6]") {
    IPAnalyzer analyzer("2001:0db8:0000:0000:0000:0000:0000:0001/64");
    REQUIRE(analyzer.get_ip()->to_string() == "2001:db8::1");
    REQUIRE(analyzer.get_network()->to_string() == "2001:db8::");
    REQUIRE(analyzer.get_netmask()->to_string() == "ffff:ffff:ffff:ffff::");
    REQUIRE(analyzer.get_broadcast()->to_string() == "2001:db8::ffff:ffff:ffff:ffff");

    auto [first, last] = analyzer.get_host_range();
    REQUIRE(first->to_string() == "2001:db8::1");
    REQUIRE(last->to_string() == "2001:db8::ffff:ffff:ffff:fffe");

    REQUIRE(analyzer.get_num_hosts() == std::numeric_limits<uint64_t>::max());
    REQUIRE(analyzer.is_private() == false);
    REQUIRE(analyzer.get_cidr() == 64);
}

TEST_CASE("IPAnalyzer IPv6 non-byte-aligned broadcast", "[ipanalyzer][ipv6]") {
    IPAnalyzer analyzer("2001:8000::1/9");
    REQUIRE(analyzer.get_network()->to_string() == "2000::");
    REQUIRE(analyzer.get_broadcast()->to_string() == "207f:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    auto [first, last] = analyzer.get_host_range();
    REQUIRE(first->to_string() == "2000::1");
    REQUIRE(last->to_string() == "207f:ffff:ffff:ffff:ffff:ffff:ffff:fffe");
}

TEST_CASE("IPAnalyzer IPv6 host range uses network address", "[ipanalyzer][ipv6]") {
    IPAnalyzer analyzer("2001:0db8:0000:0000:0000:0000:0000:0001/64");
    auto [first, last] = analyzer.get_host_range();
    REQUIRE(first->to_string() == "2001:db8::1");
    REQUIRE(last->to_string() == "2001:db8::ffff:ffff:ffff:fffe");
}

TEST_CASE("IPAnalyzer IPv6 /127 host range", "[ipanalyzer][ipv6]") {
    IPAnalyzer analyzer("2001:db8::/127");
    auto [first, last] = analyzer.get_host_range();
    REQUIRE(first->to_string() == "2001:db8::");
    REQUIRE(last->to_string() == "2001:db8::1");
}

TEST_CASE("Default CIDR values when not provided", "[ipanalyzer]") {
    SECTION("Default IPv4 CIDR is /32") {
        IPAnalyzer analyzer("192.168.0.1");
        REQUIRE(analyzer.get_cidr() == 32);
    }

    SECTION("Default IPv6 CIDR is /128") {
        IPAnalyzer analyzer("2001:0db8:0000:0000:0000:0000:0000:0001");
        REQUIRE(analyzer.get_cidr() == 128);
        REQUIRE(analyzer.get_network()->to_string() == "2001:db8::1");
        REQUIRE(analyzer.get_broadcast()->to_string() == "2001:db8::1");
        auto [first, last] = analyzer.get_host_range();
        REQUIRE(first->to_string() == "2001:db8::1");
        REQUIRE(last->to_string() == "2001:db8::1");
    }
}

TEST_CASE("Invalid IPv6 addresses and CIDR values", "[ipv6address]") {
    SECTION("Invalid IPv6 format") {
        REQUIRE_THROWS_AS(IPv6Address("2001:db8:::1"), std::invalid_argument);
    }
    SECTION("Invalid IPv6 CIDR") {
        REQUIRE_THROWS_AS(IPAnalyzer("2001:0db8:0000:0000:0000:0000:0000:0001/129"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPAnalyzer("2001:0db8:0000:0000:0000:0000:0000:0001/-1"), std::invalid_argument);
    }
}

TEST_CASE("IPv6 private address detection", "[ipv6address]") {
    IPv6Address ip1("fd00:0000:0000:0000:0000:0000:0000:0001");
    REQUIRE(ip1.is_private() == true);

    IPv6Address ip2("fc00:0000:0000:0000:0000:0000:0000:0001");
    REQUIRE(ip2.is_private() == true);

    IPv6Address ip3("fe80:0000:0000:0000:0000:0000:0000:0001");
    REQUIRE(ip3.is_private() == false);
}
