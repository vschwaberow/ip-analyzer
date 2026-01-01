# Changelog

## 0.1.5
- Fix IPv6 `::` expansion to produce correct 8-segment addresses and add regression tests.
- Fix IPv6 broadcast calculation for non-byte-aligned CIDR and add regression test.
- Fix IPv6 host range to be computed from the network address and add regression test.
- Fix IPv4 /0 netmask and host range calculation and add regression test.
- Reject IPv4 segments that contain trailing junk (e.g., `/24`).
- Add IPv6 compressed output formatting and IPv4-mapped IPv6 parsing with stricter validation.
- Expand IPv6 scope detection and /127 host range behavior.
- Support IPv4 netmask notation in CIDR parsing.
- Add `--json` and `--ip` CLI options.
- Add tests for compressed IPv6 forms, non-byte-aligned IPv6 ranges, IPv4 /31, and netmask parsing.
- Add changelog and bump displayed version to 0.1.5.

## 0.1.4
- Development (#4).
- Correct version metadata.

## 0.1.3
- Development (#3).
- Add GitHub Actions workflow for build and test on release.
- Enable manual triggering of build and test workflow.
- Remove FreeBSD from build matrix and update dependency installation steps.
- Update C++ standard from 26 to 23 in CMakeLists.txt.
- Include `<limits>` header for IPv4 network calculation.
- Disable fail-fast in build matrix for improved workflow stability.

## 0.1.2
- Add IPv4 network and broadcast calculation methods (#2).

## 0.1.1
- Add IPv6 support (#1).
- Fix a README mistake.

## 0.1.0
- Add `cmake` directory.
- Initial commit.
