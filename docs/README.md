# Documentation

Welcome to the profiler documentation. This guide will help you navigate the available resources.

## Getting started

New to profiler? Start here:

- [Quick start guide](user/QUICKSTART.md) - Get up and running in minutes
- [Configuration guide](user/CONFIGURATION.md) - Customize profiler settings
- [Command line usage](user/CLI_USAGE.md) - Complete CLI reference

## User guides

### Basic usage

- [Quick start guide](user/QUICKSTART.md) - First time setup and usage
- [Configuration guide](user/CONFIGURATION.md) - All configuration options explained
- [Command line usage](user/CLI_USAGE.md) - Command reference and examples
- [FAQ](user/FAQ.md) - Frequently asked questions

### Understanding results

- [Capability logic](../CAPABILITY_LOGIC.md) - How capabilities are detected and reported
- [Monitoring integration](MONITORING.md) - Status files and external monitoring
- [Info file schema](../INFO_FILE_SCHEMA.md) - Runtime info file format
- [State file schema](../STATE_FILE_SCHEMA.md) - Persistent state file format

## Developer documentation

### Development

- [Development guide](../DEVELOPMENT.md) - Building and contributing
- [Testing guide](developer/TESTING.md) - Hardware test suite
- [Contributing guide](../CONTRIBUTING.md) - How to contribute

### Technical reference

- [Interface staging](../INTERFACE_STAGING.md) - How interface preparation works
- [Hostapd build guide](../HOSTAPD_BUILD_AND_PATCHING_GUIDE.md) - Building hostapd from source
- [OTA testing](../tests/OTA_TESTING.md) - Over-the-air testing procedures

## Installation and upgrade

- [Installing with pipx](../INSTALLING_WITH_PIPX.md) - Install on non-WLAN Pi systems
- [Upgrading with pipx](../UPGRADING_WITH_PIPX.md) - Upgrade existing pipx installs
- [Deployment guide](../DEPLOYMENT.md) - Production deployment

## Troubleshooting

- [Known issues](../KNOWN_ISSUES.md) - Common problems and solutions
- [FAQ](user/FAQ.md) - Frequently asked questions
- [Investigations](../INVESTIGATIONS.md) - Technical investigations and findings

## Project information

- [Release notes](../RELEASE_NOTES.md) - Version history and changes
- [Style guide](../STYLE_GUIDE.md) - Code style and conventions
- [Contributing](../CONTRIBUTING.md) - How to contribute to the project

## Quick links

### Common tasks

- [Start profiling](user/QUICKSTART.md#start-the-profiler)
- [Configure the passphrase](user/CONFIGURATION.md#configuring-the-passphrase)
- [Change the channel](user/CLI_USAGE.md#change-the-channel)
- [Enable debug logging](user/CLI_USAGE.md#debug-mode)

### Reference

- [All CLI options](user/CLI_USAGE.md)
- [Configuration options](user/CONFIGURATION.md#configuration-options)
- [Security modes](user/CONFIGURATION.md#security-settings)
- [Capability detection](../CAPABILITY_LOGIC.md)

## Documentation structure

```
docs/
├── README.md (this file)
├── MONITORING.md - Status files and monitoring
├── user/
│   ├── QUICKSTART.md - Getting started
│   ├── CONFIGURATION.md - Configuration options
│   ├── CLI_USAGE.md - Command line reference
│   └── FAQ.md - Frequently asked questions
└── developer/
    └── TESTING.md - Hardware testing guide
```

## Contributing to documentation

Documentation improvements are welcome! Please see the [contributing guide](../CONTRIBUTING.md) for details on how to submit changes.

## Getting help

- Check the [FAQ](user/FAQ.md)
- Review [known issues](../KNOWN_ISSUES.md)
- Create an issue for bugs
