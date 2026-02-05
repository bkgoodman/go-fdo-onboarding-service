# FIDO Device Onboarding (FDO) Onborarding Service (Server)

## Overview

This application provides basic functionality for a network service to onboard device, and provide basic configuration data to them. Per FDO protocol, this applcation will provide TO1 and TO2 services to the device. FDO provides a mechanism for guarenteed mutual attestation between device and onboarding service prior to onboarding, afterwhich all configuration data is exchanged between the device and oboarding service via an encrypted channel.


## Setup

### Prerequisites

- Go 1.21 or later
- Git

### Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd go-fdo-onboarding-service
```

2. Initialize the git submodule:
```bash
git submodule update --init --recursive
```

3. Build the application:
```bash
go build -o fdo-server .
```

## Configuration

## Dependencies

- [go-fdo](https://github.com/bkgoodman/go-fdo): Main FDO library (included as git submodule)
- Standard Go library packages for cryptography, networking, and HTTP transport

## License

This project follows the same license as the go-fdo library: Apache License 2.0

## Contributing

This is a demonstration/stub application. For production use, you would need to:

1. Implement the credential storage/retrieval functions
2. Add proper error handling and logging
3. Implement security best practices for credential management
4. Add comprehensive testing
5. Consider adding configuration file support

## References

- [FIDO Device Onboard Protocol Specification](https://fidoalliance.org/specs/fdo/)
- [go-fdo Library Documentation](https://github.com/bkgoodman/go-fdo)
- [FIDO Alliance](https://fidoalliance.org/)
