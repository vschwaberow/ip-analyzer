# Changelog

## 0.1.5
- Fix IPv6 `::` expansion to produce correct 8-segment addresses and add regression tests.
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
