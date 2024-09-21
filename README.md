# IP Analyzer

IP Analyzer is a command-line tool that provides detailed information about IP addresses and their associated network properties. It offers a user-friendly interface with a visually appealing Commodore Amiga Copper-style output.

## Features

- Analyze IP addresses with CIDR notation
- Display IP address details in both decimal and binary formats
- Show network address, netmask, and broadcast address
- Calculate usable IP range and number of hosts
- Determine if the IP address is private
- Present results in a colorful, easy-to-read format

## Prerequisites

To build and run this project, you need:

- C++17 compatible compiler (e.g., GCC 7+, Clang 5+, or MSVC 2017+)
- CMake 3.10 or higher
- fmt library (will be automatically downloaded if not found)

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

To analyze an IP address, run the program and enter the IP address with CIDR notation:

```bash
./build/ip-analyzer
Enter an IP address with CIDR notation: 192.168.178.0/24
```

When prompted, enter an IP address with or without CIDR notation. The tool will automatically detect whether it's an IPv4 or IPv6 address.

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
- IPv4-mapped IPv6 addresses: `::ffff:192.0.2.128`

The program will display detailed information about the IP address.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Pull Requests

If you find a bug or want to contribute to the project, feel free to submit a pull request.
