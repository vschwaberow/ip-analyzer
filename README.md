# IP Analyzer

IP Analyzer is a command-line tool that provides detailed information about IP addresses and their associated network properties. It offers a user-friendly interface with a visually appealing Commodore Amiga Copper-style output.

## Features

- Analyze IP addresses with CIDR notation
- Display IP address details in both decimal and binary formats
- Show network address, netmask, and broadcast address
- Calculate usable IP range and number of hosts
- Determine if the IP address is private
- Present results in a colorful, easy-to-read format
- Support IPv4 netmask notation (e.g., `/255.255.255.0`)
- Offer JSON output and non-interactive `--ip` and `--stdin` modes
- Provide `--compact` and `--no-color` output modes
- Test containment, overlap, adjacency, and a full `--relate` taxonomy
- Convert an inclusive address range to a minimal CIDR set
- List usable host addresses (`--list-ips`)
- Exclude, intersect, and aggregate CIDRs or ranges
- Split prefixes and select the n-th usable host

## Prerequisites

To build and run this project, you need:

- C++23 compatible compiler with `<print>` support:
  - GCC >= 14.1
  - Clang >= 18 (with libc++ >= 18)
  - MSVC 2022 (v17.7+)
- CMake 3.22 or higher

## Building the Project

1. Clone the repository:

```bash
git clone https://github.com/vschwaberow/ip-analyzer.git
```

2. Build using CMake:

```bash
cmake -S . -B ./build
cmake --build build --config Release
```

3. Run the executable:

```bash
./build/ip-analyzer
```

4. You can also run the tests:

```bash
./build/ip_analyzer_tests
```

## Usage

To analyze an IP address directly, provide it as an argument:

```bash
./build/ip-analyzer 192.168.178.0/24
```

To run in interactive mode, use `--interactive` or `-i`:

```bash
./build/ip-analyzer --interactive
```

The tool will automatically detect whether it's an IPv4 or IPv6 address.

You can also pass arguments via `--ip`:

```bash
./build/ip-analyzer --ip 192.168.1.1/24 --json
```

The JSON output includes a schema identifier (`ip-analyzer/1`) and the app version.

You can process multiple inputs from stdin:

```bash
printf "192.168.1.1/24\n2001:db8::1/64\n" | ./build/ip-analyzer --stdin --compact
```

Containment, overlap, range aggregation, and host listing:

```bash
./build/ip-analyzer 192.168.1.0/24 --contains 192.168.1.10
./build/ip-analyzer 192.168.1.0/24 --overlaps 192.168.1.128/25
./build/ip-analyzer 192.168.1.10-192.168.1.50
./build/ip-analyzer --range 2001:db8::1-2001:db8::5 --json
./build/ip-analyzer 192.168.1.0/30 --list-ips
./build/ip-analyzer --no-color "2001:db8::1 - 2001:db8::5" --list-ips
./build/ip-analyzer --compact --no-color 192.168.1.0/25 --relate 192.168.1.128/25
./build/ip-analyzer --no-color 10.0.0.0/8 --exclude 10.1.0.0/16
./build/ip-analyzer --no-color 192.168.1.0/24 --split 4
./build/ip-analyzer --no-color 192.168.1.0/24 --nth -1
printf "10.0.0.0/16\n10.1.0.0/16\n" | ./build/ip-analyzer --stdin --aggregate
```

`--list-ips` prints one usable host per line and refuses networks larger than 1,048,576 hosts.

## Examples

### IPv4 Example

Input:
```bash
Enter an IP address with CIDR notation: 192.168.178.0/24
```
## Supported IPv6 Formats

The IP Analyzer supports various IPv6 address formats, including:

- Full notation: `2001:0db8:85a3:0000:0000:8a2e:0370:7334`
- Compressed notation: `2001:db8:85a3::8a2e:370:7334`
- IPv4-mapped IPv6 addresses: `::ffff:192.0.2.128` (outputs as `::ffff:192.0.2.128`)

The program will display detailed information about the IP address.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Releases

Published GitHub Releases include ready-to-run binaries:

- `ip-analyzer-linux-x86_64`
- `ip-analyzer-macos-universal`
- `ip-analyzer-windows-x86_64.exe`

## Changelog

Release notes are tracked in [CHANGELOG.md](CHANGELOG.md).

## Pull Requests

If you find a bug or want to contribute to the project, feel free to submit a pull request.
