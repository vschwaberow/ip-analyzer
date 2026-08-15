// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: src/tests/ip_analyzer_tests.cc
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>
#include "ip_analyzer.hh"
#include <limits>
#include <vector>

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
        REQUIRE_THROWS_AS(IPAnalyzer("192.168.0.1/256"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPAnalyzer("192.168.0.1/288"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPAnalyzer("192.168.0.1/1000"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPAnalyzer("192.168.0.1/-1"), std::invalid_argument);
    }

    SECTION("IPv4 netmask notation") {
        IPAnalyzer analyzer("192.168.0.1/255.255.255.0");
        REQUIRE(analyzer.get_cidr() == 24);
        REQUIRE(analyzer.get_netmask()->to_string() == "255.255.255.0");
        REQUIRE_THROWS_AS(IPAnalyzer("192.168.0.1/255.0.255.0"), std::invalid_argument);
    }

    SECTION("Whitespace trimming") {
        IPAnalyzer analyzer1("  192.168.0.1/24  ");
        REQUIRE(analyzer1.get_ip()->to_string() == "192.168.0.1");
        REQUIRE(analyzer1.get_cidr() == 24);

        IPAnalyzer analyzer2("192.168.0.1 / 24");
        REQUIRE(analyzer2.get_ip()->to_string() == "192.168.0.1");
        REQUIRE(analyzer2.get_cidr() == 24);

        IPAnalyzer analyzer3("  2001:db8::1/64  ");
        REQUIRE(analyzer3.get_ip()->to_string() == "2001:db8::1");
        REQUIRE(analyzer3.get_cidr() == 64);

        REQUIRE_THROWS_AS(IPAnalyzer("   "), std::invalid_argument);
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

    REQUIRE(analyzer.get_num_hosts() == std::numeric_limits<uint64_t>::max() - 1);
    REQUIRE(analyzer.is_private() == false);
    REQUIRE(analyzer.get_cidr() == 64);
}

TEST_CASE("IPAnalyzer IPv6 host count matches usable range", "[ipanalyzer][ipv6]") {
    REQUIRE(IPAnalyzer("2001:db8::/120").get_num_hosts() == 254);
    REQUIRE(IPAnalyzer("2001:db8::/96").get_num_hosts() == 4294967294ULL);
    REQUIRE(IPAnalyzer("2001:db8::/126").get_num_hosts() == 2);
    REQUIRE(IPAnalyzer("2001:db8::/127").get_num_hosts() == 2);
    REQUIRE(IPAnalyzer("2001:db8::1/128").get_num_hosts() == 1);
    REQUIRE(IPAnalyzer("2001:db8::/64").get_num_hosts() ==
            std::numeric_limits<uint64_t>::max() - 1);
    REQUIRE(IPAnalyzer("2001:db8::/63").get_num_hosts() ==
            std::numeric_limits<uint64_t>::max());
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
        REQUIRE_THROWS_AS(IPAnalyzer("2001:0db8:0000:0000:0000:0000:0000:0001/256"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPAnalyzer("2001:0db8:0000:0000:0000:0000:0000:0001/300"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPAnalyzer("2001:0db8:0000:0000:0000:0000:0000:0001/1000"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPAnalyzer("2001:0db8:0000:0000:0000:0000:0000:0001/-1"), std::invalid_argument);
    }
}

TEST_CASE("IPv4-mapped private address classification", "[ipv6address]") {
    REQUIRE(IPv6Address("::ffff:192.168.1.1").is_private() == true);
    REQUIRE(IPv6Address("::ffff:10.0.0.1").is_private() == true);
    REQUIRE(IPv6Address("::ffff:172.16.5.1").is_private() == true);
    REQUIRE(IPv6Address("::ffff:8.8.8.8").is_private() == false);
    REQUIRE(IPv6Address("::ffff:192.0.2.128").is_ipv4_mapped() == true);
    REQUIRE(IPv6Address("2001:db8::1").is_ipv4_mapped() == false);
    REQUIRE(IPAnalyzer("::ffff:192.168.1.1").is_private() == true);
}

TEST_CASE("IPv6 private address detection", "[ipv6address]") {
    IPv6Address ip1("fd00:0000:0000:0000:0000:0000:0000:0001");
    REQUIRE(ip1.is_private() == true);

    IPv6Address ip2("fc00:0000:0000:0000:0000:0000:0000:0001");
    REQUIRE(ip2.is_private() == true);

    IPv6Address ip3("fe80:0000:0000:0000:0000:0000:0000:0001");
    REQUIRE(ip3.is_private() == false);
}

TEST_CASE("IP relations contain and overlap", "[ipanalyzer][relations]") {
    SECTION("Host and subnet containment") {
        REQUIRE(IPAnalyzer("192.168.1.0/24").contains(IPAnalyzer("192.168.1.10")));
        REQUIRE(IPAnalyzer("192.168.1.0/24").contains(IPAnalyzer("192.168.1.128/25")));
        REQUIRE_FALSE(IPAnalyzer("192.168.1.0/24").contains(IPAnalyzer("192.168.2.1")));
        REQUIRE_FALSE(IPAnalyzer("192.168.1.128/25").contains(IPAnalyzer("192.168.1.0/24")));
        REQUIRE(IPAnalyzer("10.0.0.0/8").contains(IPAnalyzer("10.0.0.0/8")));
    }

    SECTION("IPv6 containment") {
        REQUIRE(IPAnalyzer("2001:db8::/32").contains(IPAnalyzer("2001:db8:1::1")));
        REQUIRE(IPAnalyzer("2001:db8::/32").contains(IPAnalyzer("2001:db8:aaaa::/48")));
        REQUIRE_FALSE(IPAnalyzer("2001:db8::/32").contains(IPAnalyzer("2001:db9::1")));
    }

    SECTION("Overlap is symmetric and detects partial intersection") {
        REQUIRE(IPAnalyzer("192.168.1.0/24").overlaps(IPAnalyzer("192.168.1.128/25")));
        REQUIRE(IPAnalyzer("192.168.1.128/25").overlaps(IPAnalyzer("192.168.1.0/24")));
        REQUIRE(IPAnalyzer("10.0.0.0/8").overlaps(IPAnalyzer("10.1.2.0/24")));
        REQUIRE_FALSE(IPAnalyzer("192.168.1.0/25").overlaps(IPAnalyzer("192.168.1.128/25")));
        REQUIRE(IPAnalyzer("2001:db8::/32").overlaps(IPAnalyzer("2001:db8:1::/48")));
        REQUIRE_FALSE(IPAnalyzer("2001:db8::/33").overlaps(IPAnalyzer("2001:db8:8000::/33")));
    }

    SECTION("Family mismatch is an error") {
        REQUIRE_THROWS_AS(IPAnalyzer("192.168.1.0/24").contains(IPAnalyzer("2001:db8::1")),
                          std::invalid_argument);
        REQUIRE_THROWS_AS(IPAnalyzer("192.168.1.0/24").overlaps(IPAnalyzer("2001:db8::/64")),
                          std::invalid_argument);
    }
}

TEST_CASE("Range to minimal CIDR prefixes", "[ipanalyzer][range]") {
    SECTION("Classic IPv4 example") {
        const auto prefixes =
            IPAnalyzer::cidrs_covering_range("192.168.1.10", "192.168.1.50");
        REQUIRE(prefixes == std::vector<std::string>{
            "192.168.1.10/31",
            "192.168.1.12/30",
            "192.168.1.16/28",
            "192.168.1.32/28",
            "192.168.1.48/31",
            "192.168.1.50/32",
        });
    }

    SECTION("Aligned block, singleton, and full space") {
        REQUIRE(IPAnalyzer::cidrs_covering_range("10.0.0.0", "10.0.0.255") ==
                std::vector<std::string>{"10.0.0.0/24"});
        REQUIRE(IPAnalyzer::cidrs_covering_range("192.168.1.1", "192.168.1.1") ==
                std::vector<std::string>{"192.168.1.1/32"});
        REQUIRE(IPAnalyzer::cidrs_covering_range("0.0.0.0", "255.255.255.255") ==
                std::vector<std::string>{"0.0.0.0/0"});
    }

    SECTION("IPv6 ranges") {
        REQUIRE(IPAnalyzer::cidrs_covering_range("2001:db8::1", "2001:db8::5") ==
                std::vector<std::string>{
                    "2001:db8::1/128",
                    "2001:db8::2/127",
                    "2001:db8::4/127",
                });
        REQUIRE(IPAnalyzer::cidrs_covering_range("2001:db8::", "2001:db8::ffff") ==
                std::vector<std::string>{"2001:db8::/112"});
    }

    SECTION("Invalid ranges") {
        REQUIRE_THROWS_AS(IPAnalyzer::cidrs_covering_range("192.168.1.50", "192.168.1.10"),
                          std::invalid_argument);
        REQUIRE_THROWS_AS(IPAnalyzer::cidrs_covering_range("192.168.1.1", "2001:db8::1"),
                          std::invalid_argument);
    }

    SECTION("Range parser accepts hyphen and spaced hyphen") {
        auto compact = IPAnalyzer::parse_address_range("192.168.1.10-192.168.1.50");
        REQUIRE(compact.has_value());
        REQUIRE(compact->first == "192.168.1.10");
        REQUIRE(compact->second == "192.168.1.50");

        auto spaced = IPAnalyzer::parse_address_range("  2001:db8::1 - 2001:db8::5  ");
        REQUIRE(spaced.has_value());
        REQUIRE(spaced->first == "2001:db8::1");
        REQUIRE(spaced->second == "2001:db8::5");

        REQUIRE_FALSE(IPAnalyzer::parse_address_range("192.168.1.0/24").has_value());
    }
}

TEST_CASE("Usable host listing respects range and safety limit", "[ipanalyzer][list]") {
    SECTION("IPv4 usable hosts") {
        REQUIRE(IPAnalyzer("192.168.1.0/30").list_usable_hosts() ==
                std::vector<std::string>{"192.168.1.1", "192.168.1.2"});
        REQUIRE(IPAnalyzer("192.168.1.1/32").list_usable_hosts() ==
                std::vector<std::string>{"192.168.1.1"});
        REQUIRE(IPAnalyzer("192.168.1.0/31").list_usable_hosts() ==
                std::vector<std::string>{"192.168.1.0", "192.168.1.1"});
    }

    SECTION("IPv6 usable hosts") {
        REQUIRE(IPAnalyzer("2001:db8::/126").list_usable_hosts() ==
                std::vector<std::string>{"2001:db8::1", "2001:db8::2"});
        REQUIRE(IPAnalyzer("2001:db8::1/128").list_usable_hosts() ==
                std::vector<std::string>{"2001:db8::1"});
    }

    SECTION("Safety limit") {
        REQUIRE_THROWS_AS(IPAnalyzer("10.0.0.0/8").list_usable_hosts(), std::invalid_argument);
        REQUIRE_THROWS_AS(IPAnalyzer("2001:db8::/64").list_usable_hosts(), std::invalid_argument);
        REQUIRE_THROWS_AS(IPAnalyzer("192.168.0.0/24").list_usable_hosts(16),
                          std::invalid_argument);
    }
}

TEST_CASE("Inclusive range host listing", "[ipanalyzer][list]") {
    REQUIRE(IPAnalyzer::list_addresses_in_range("2001:db8::1", "2001:db8::5") ==
            std::vector<std::string>{
                "2001:db8::1",
                "2001:db8::2",
                "2001:db8::3",
                "2001:db8::4",
                "2001:db8::5",
            });
    REQUIRE(IPAnalyzer::list_addresses_in_range("192.168.1.10", "192.168.1.12") ==
            std::vector<std::string>{"192.168.1.10", "192.168.1.11", "192.168.1.12"});
    REQUIRE_THROWS_AS(IPAnalyzer::list_addresses_in_range("10.0.0.0", "10.255.255.255"),
                      std::invalid_argument);
}

TEST_CASE("Prefix relation taxonomy", "[ipanalyzer][relations]") {
    REQUIRE(IPAnalyzer("192.168.1.0/24").relate(IPAnalyzer("192.168.1.0/24")) ==
            PrefixRelation::Equal);
    REQUIRE(IPAnalyzer("192.168.1.0/24").relate(IPAnalyzer("192.168.1.128/25")) ==
            PrefixRelation::Contains);
    REQUIRE(IPAnalyzer("192.168.1.128/25").relate(IPAnalyzer("192.168.1.0/24")) ==
            PrefixRelation::ContainedBy);
    REQUIRE(IPAnalyzer("192.168.1.0/25").relate(IPAnalyzer("192.168.1.128/25")) ==
            PrefixRelation::Adjacent);
    REQUIRE(IPAnalyzer("192.168.1.0/25").is_adjacent(IPAnalyzer("192.168.1.128/25")));
    REQUIRE(IPAnalyzer("10.0.0.0/8").relate(IPAnalyzer("11.0.0.0/8")) ==
            PrefixRelation::Adjacent);
    REQUIRE(IPAnalyzer("10.0.0.0/8").relate(IPAnalyzer("8.8.8.8/32")) ==
            PrefixRelation::Disjoint);
    REQUIRE(IPAnalyzer("2001:db8::/32").relate(IPAnalyzer("2001:db8:1::/48")) ==
            PrefixRelation::Contains);
}

TEST_CASE("IPv4-mapped addresses relate to IPv4 prefixes", "[ipanalyzer][relations]") {
    REQUIRE(IPAnalyzer("192.168.1.0/24").contains(IPAnalyzer("::ffff:192.168.1.10")));
    REQUIRE(IPAnalyzer("::ffff:192.168.1.10").contains(IPAnalyzer("192.168.1.10")));
    REQUIRE(IPAnalyzer("192.168.1.0/24").overlaps(IPAnalyzer("::ffff:192.168.1.0/120")));
    REQUIRE(IPAnalyzer("10.0.0.0/8").relate(IPAnalyzer("::ffff:11.0.0.0/104")) ==
            PrefixRelation::Adjacent);
}

TEST_CASE("Next and previous aligned prefixes", "[ipanalyzer][relations]") {
    REQUIRE(IPAnalyzer("192.168.1.0/24").next_prefix() == "192.168.2.0/24");
    REQUIRE(IPAnalyzer("192.168.1.0/24").prev_prefix() == "192.168.0.0/24");
    REQUIRE(IPAnalyzer("2001:db8::/32").next_prefix() == "2001:db9::/32");
    REQUIRE_THROWS_AS(IPAnalyzer("255.255.255.0/24").next_prefix(), std::invalid_argument);
    REQUIRE_THROWS_AS(IPAnalyzer("0.0.0.0/8").prev_prefix(), std::invalid_argument);
    REQUIRE_THROWS_AS(IPAnalyzer("0.0.0.0/0").next_prefix(), std::invalid_argument);
}

TEST_CASE("Exclude and intersect produce minimal CIDRs", "[ipanalyzer][relations]") {
    REQUIRE(IPAnalyzer("192.168.1.0/24").exclude(IPAnalyzer("192.168.1.128/25")) ==
            std::vector<std::string>{"192.168.1.0/25"});
    REQUIRE(IPAnalyzer("10.0.0.0/8").intersect(IPAnalyzer("10.1.2.0/24")) ==
            std::vector<std::string>{"10.1.2.0/24"});
    REQUIRE(IPAnalyzer("192.168.1.0/25").intersect(IPAnalyzer("192.168.1.128/25")).empty());
    REQUIRE(IPAnalyzer::exclude_from_range("192.168.1.10", "192.168.1.20", "192.168.1.12/31") ==
            std::vector<std::string>{"192.168.1.10/31", "192.168.1.14/31", "192.168.1.16/30",
                                     "192.168.1.20/32"});
}

TEST_CASE("Aggregate merges overlapping and adjacent prefixes", "[ipanalyzer][relations]") {
    const std::vector<std::string> inputs{"10.0.0.0/16", "10.1.0.0/16"};
    REQUIRE(IPAnalyzer::aggregate(inputs) == std::vector<std::string>{"10.0.0.0/15"});
    const std::vector<std::string> nested{"192.168.0.0/16", "192.168.1.0/24"};
    REQUIRE(IPAnalyzer::aggregate(nested) == std::vector<std::string>{"192.168.0.0/16"});
}

TEST_CASE("Split and nth host selection", "[ipanalyzer][relations]") {
    REQUIRE(IPAnalyzer("192.168.1.0/24").split(26) ==
            std::vector<std::string>{
                "192.168.1.0/26",
                "192.168.1.64/26",
                "192.168.1.128/26",
                "192.168.1.192/26",
            });
    REQUIRE_THROWS_AS(IPAnalyzer("192.168.1.0/24").split(24), std::invalid_argument);
    REQUIRE(IPAnalyzer("192.168.1.0/24").nth_address(0) == "192.168.1.1");
    REQUIRE(IPAnalyzer("192.168.1.0/24").nth_address(-1) == "192.168.1.254");
    REQUIRE_THROWS_AS(IPAnalyzer("192.168.1.0/24").nth_address(254), std::invalid_argument);
    REQUIRE(IPAnalyzer::nth_address_in_range("2001:db8::1", "2001:db8::5", 0) == "2001:db8::1");
    REQUIRE(IPAnalyzer::nth_address_in_range("2001:db8::1", "2001:db8::5", -1) == "2001:db8::5");
}
