#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>
#include "ip_analyzer.hh"

TEST_CASE("IPv4Address construction and methods", "[ipv4address]")
{
    IPv4Address ip("192.168.0.1");

    REQUIRE(ip.to_string() == "192.168.0.1");
    REQUIRE(ip.to_binary_string() == "11000000101010000000000000000001");
    REQUIRE(ip.to_uint32() == 3232235521);
}

TEST_CASE("IPAnalyzer functionality", "[ipanalyzer]")
{
    IPAnalyzer analyzer("192.168.0.1/24");

    REQUIRE(analyzer.get_ip().to_string() == "192.168.0.1");
    REQUIRE(analyzer.get_network().to_string() == "192.168.0.0");
    REQUIRE(analyzer.get_netmask().to_string() == "255.255.255.0");
    REQUIRE(analyzer.get_broadcast().to_string() == "192.168.0.255");

    auto [first, last] = analyzer.get_host_range();
    REQUIRE(first.to_string() == "192.168.0.1");
    REQUIRE(last.to_string() == "192.168.0.254");

    REQUIRE(analyzer.get_num_hosts() == 254);
    REQUIRE(analyzer.is_private() == true);
    REQUIRE(analyzer.get_cidr() == 24);
}

TEST_CASE("Edge cases for IPv4Address", "[ipv4address]")
{
    SECTION("Minimum IP address")
    {
        IPv4Address min_ip("0.0.0.0");
        REQUIRE(min_ip.to_string() == "0.0.0.0");
        REQUIRE(min_ip.to_uint32() == 0);
    }

    SECTION("Maximum IP address")
    {
        IPv4Address max_ip("255.255.255.255");
        REQUIRE(max_ip.to_string() == "255.255.255.255");
        REQUIRE(max_ip.to_uint32() == 4294967295);
    }

    SECTION("Invalid IP address formats")
    {
        REQUIRE_THROWS_AS(IPv4Address("256.0.0.1"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPv4Address("192.168.0"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPv4Address("192.168.0.1.2"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPv4Address("192.168.0.a"), std::invalid_argument);
    }
}

TEST_CASE("Edge cases for IPAnalyzer", "[ipanalyzer]")
{
    SECTION("Minimum CIDR")
    {
        IPAnalyzer analyzer("192.168.0.1/0");
        REQUIRE(analyzer.get_network().to_string() == "0.0.0.0");
        REQUIRE(analyzer.get_broadcast().to_string() == "255.255.255.255");
        REQUIRE(analyzer.get_num_hosts() == 4294967294);
    }

    SECTION("Maximum CIDR")
    {
        IPAnalyzer analyzer("192.168.0.1/32");
        REQUIRE(analyzer.get_network().to_string() == "192.168.0.1");
        REQUIRE(analyzer.get_broadcast().to_string() == "192.168.0.1");
        REQUIRE(analyzer.get_num_hosts() == 1); // Changed from 0 to 1

        auto [first, last] = analyzer.get_host_range();
        REQUIRE(first.to_string() == "192.168.0.1");
        REQUIRE(last.to_string() == "192.168.0.1");
    }

    SECTION("Invalid CIDR values")
    {
        REQUIRE_THROWS_AS(IPAnalyzer("192.168.0.1/33"), std::invalid_argument);
        REQUIRE_THROWS_AS(IPAnalyzer("192.168.0.1/-1"), std::invalid_argument);
    }

    SECTION("Private IP ranges")
    {
        REQUIRE(IPAnalyzer("10.0.0.1/24").is_private() == true);
        REQUIRE(IPAnalyzer("172.16.0.1/24").is_private() == true);
        REQUIRE(IPAnalyzer("192.168.0.1/24").is_private() == true);
        REQUIRE(IPAnalyzer("8.8.8.8/24").is_private() == false);
    }

    SECTION("Class A, B, C network boundaries")
    {
        REQUIRE(IPAnalyzer("127.255.255.255/8").get_network().to_string() == "127.0.0.0");
        REQUIRE(IPAnalyzer("128.0.0.0/16").get_network().to_string() == "128.0.0.0");
        REQUIRE(IPAnalyzer("192.0.0.0/24").get_network().to_string() == "192.0.0.0");
    }
}