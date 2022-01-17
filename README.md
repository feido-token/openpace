# OpenPACE *- Cryptographic library for EAC version 2*

OpenPACE implements Extended Access Control (EAC) version 2 as specified in
BSI TR-03110. OpenPACE comprises support for the following protocols:

- **Password Authenticated Connection Establishment (PACE)** Establish a secure
  channel with a strong key between two parties that only share a weak secret.
- **Terminal Authentication (TA)** Verify/prove the terminal's certificate (or
  rather certificate chain) and secret key.
- **Chip Authentication (CA)** Establish a secure channel based on the chip's
  static key pair proving its authenticy.

Furthermore, OpenPACE also supports Card Verifiable Certificates (CV
Certificates) as well as easy to use wrappers for using the established secure
channels.

The handlers for looking up trust anchors during TA and CA (i.e. the CVCA
and the CSCA certificates) can be customized. By default, the appropriate
certificates will be looked up in the file system.

OpenPACE supports all variants of PACE (DH/ECDH, GM/IM), TA
(RSASSA-PKCS1-v1_5/RSASSA-PSS/ECDSA), CA (DH/ECDH) and all standardized
domain parameters (GFP/ECP).
   

OpenPACE is implemented as C-library and comes with native language wrappers
for:

- Python
- Ruby
- Javascript
- Java
- Go

[![Ubuntu CI status image](https://github.com/frankmorgner/openpace/actions/workflows/ubuntu.yml/badge.svg)](https://github.com/frankmorgner/openpace/actions/workflows/ubuntu.yml) [![macOS CI status image](https://github.com/frankmorgner/openpace/actions/workflows/macos.yml/badge.svg)](https://github.com/frankmorgner/openpace/actions/workflows/macos.yml) [![Windows CI status image](https://img.shields.io/appveyor/ci/frankmorgner/openpace/master.svg?label=Windows%20build)](https://ci.appveyor.com/project/frankmorgner/openpace) [![Coverity Scan status image](https://img.shields.io/coverity/scan/1789.svg?label=Coverity%20scan)](https://scan.coverity.com/projects/1789) [![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/frankmorgner/openpace.svg)](https://lgtm.com/projects/g/frankmorgner/openpace/context:cpp)

Please refer to [our project's website](http://frankmorgner.github.io/openpace/) for more information.

## License

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

## Tested Platforms

- Windows
- Linux (Debian, Ubuntu, SUSE, OpenMoko)
- FreeBSD
- Mac OS
- Solaris
- Android
- Javascript
