// SPDX-License-Identifier: MIT
// Project: ip-analyzer
// File: tests/cli_tests.cc
// Author: Volker Schwaberow <volker@schwaberow.de>
// Copyright (c) 2024 Volker Schwaberow

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <sstream>
#include "cli_app.hh"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

class StdoutCapture {
public:
    StdoutCapture() {
        fflush(stdout);
        old_stdout = dup(STDOUT_FILENO);
        
        if (pipe(pipe_fds) != 0) {
            throw std::runtime_error("Failed to create pipe");
        }
        
        dup2(pipe_fds[1], STDOUT_FILENO);
        close(pipe_fds[1]);
    }
    
    ~StdoutCapture() {
        fflush(stdout);
        dup2(old_stdout, STDOUT_FILENO);
        close(old_stdout);
    }
    
    std::string get_output() {
        fflush(stdout);

        int flags = fcntl(pipe_fds[0], F_GETFL);
        fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK);
        
        std::string result;
        char buffer[4096];
        ssize_t bytes;
        
        int timeout = 100;
        while (timeout > 0) {
            bytes = read(pipe_fds[0], buffer, sizeof(buffer) - 1);
            
            if (bytes > 0) {
                buffer[bytes] = '\0';
                result += buffer;
            } else if (bytes == 0 || (bytes == -1 && errno != EAGAIN)) {
                break;
            } else {
                usleep(1000);
                timeout--;
            }
        }
        
        close(pipe_fds[0]);
        
        return result;
    }
    
private:
    int old_stdout;
    int pipe_fds[2];
};

class MockIPAnalyzerApp : public ip_analyzer::IPAnalyzerApp {
public:
    std::string getVersionOutput() {
        std::stringstream ss;
        printVersionTo(ss);
        return ss.str();
    }
    
    void printVersionTo(std::ostream& os) const {
        os << ip_analyzer::kAppName << " version " << ip_analyzer::kVersion << std::endl;
        os << "Copyright (c) 2024 " << ip_analyzer::kAuthor << std::endl;
    }
};

TEST_CASE("Command line flags", "[cli]") {
    using namespace ip_analyzer;
    
    SECTION("Version flag short form (-v)") {
        int result;
        std::string output;
        
        {
            StdoutCapture capture;
            const char* args[] = {"ip-analyzer", "-v"};
            result = IPAnalyzerApp().Run(std::span<const char*>(args, 2));
            output = capture.get_output();
        }
        
        REQUIRE(result == 0);
        REQUIRE_THAT(output, Catch::Matchers::ContainsSubstring(std::string(kAppName)));
        REQUIRE_THAT(output, Catch::Matchers::ContainsSubstring(std::string(kVersion)));
        REQUIRE_THAT(output, Catch::Matchers::ContainsSubstring(std::string(kAuthor)));
    }
    
    SECTION("Version flag long form (--version)") {
        StdoutCapture capture;
        
        const char* args[] = {"ip-analyzer", "--version"};
        int result = IPAnalyzerApp().Run(std::span<const char*>(args, 2));
        
        std::string output = capture.get_output();
        
        REQUIRE(result == 0);
        REQUIRE_THAT(output, Catch::Matchers::ContainsSubstring(std::string(kAppName)));
        REQUIRE_THAT(output, Catch::Matchers::ContainsSubstring(std::string(kVersion)));
        REQUIRE_THAT(output, Catch::Matchers::ContainsSubstring(std::string(kAuthor)));
    }
}

TEST_CASE("JSON output contains schema and version", "[cli]") {
    using namespace ip_analyzer;

    StdoutCapture capture;
    const char* args[] = {"ip-analyzer", "--json", "--ip", "192.168.0.1/24"};
    int result = IPAnalyzerApp().Run(std::span<const char*>(args, 4));
    std::string output = capture.get_output();

    REQUIRE(result == 0);
    REQUIRE_THAT(output, Catch::Matchers::ContainsSubstring("\"schema\": \"ip-analyzer/1\""));
    REQUIRE_THAT(output, Catch::Matchers::ContainsSubstring(std::string(kVersion)));
}

TEST_CASE("Stdin input supports multiple lines", "[cli]") {
    using namespace ip_analyzer;

    std::istringstream input("192.168.0.1/24\n2001:db8::1/64\n");
    std::streambuf* old_buf = std::cin.rdbuf(input.rdbuf());

    StdoutCapture capture;
    const char* args[] = {"ip-analyzer", "--stdin", "--compact"};
    int result = IPAnalyzerApp().Run(std::span<const char*>(args, 3));
    std::string output = capture.get_output();

    std::cin.rdbuf(old_buf);

    REQUIRE(result == 0);
    REQUIRE_THAT(output, Catch::Matchers::ContainsSubstring("192.168.0.1"));
    REQUIRE_THAT(output, Catch::Matchers::ContainsSubstring("2001:db8::1"));
}

TEST_CASE("Version flag output", "[cli]") {
    using namespace ip_analyzer;
    
    MockIPAnalyzerApp app;
    std::string output = app.getVersionOutput();
    
    REQUIRE_THAT(output, Catch::Matchers::ContainsSubstring(std::string(kAppName)));
    REQUIRE_THAT(output, Catch::Matchers::ContainsSubstring(std::string(kVersion)));
    REQUIRE_THAT(output, Catch::Matchers::ContainsSubstring(std::string(kAuthor)));
}
