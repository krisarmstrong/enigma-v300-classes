# Enigma V300 Classes

[![CI](https://github.com/krisarmstrong/enigma-v300-classes/actions/workflows/ci.yml/badge.svg)](https://github.com/krisarmstrong/enigma-v300-classes/actions)
[![Coverage](https://img.shields.io/badge/coverage-80%25-green)](https://github.com/krisarmstrong/enigma-v300-classes)
[![PyPI](https://img.shields.io/pypi/v/enigma-v300-classes.svg)](https://pypi.org/project/enigma-v300-classes/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/krisarmstrong/enigma-v300-classes/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)

## Overview
Python implementation of Fluke option key calculator using object-oriented design (EnigmaC, Enigma2C, EnigmaMenu classes). Generates and validates option keys for Fluke network testing devices using EnigmaC (NetTool, 10-digit serial) and Enigma2C (other products, 7-digit serial) ciphers.

- **Author**: Kris Armstrong
- **Version**: 3.0.1
- **License**: MIT

## Features
- Generates option keys for NetTool and other Fluke products.
- Validates option keys against serial numbers and options.
- Interactive menu with product/option selection.
- Command-line support with logging.

## Installation
```bash
git clone git@github.com:krisarmstrong/enigma-v300-classes.git
cd enigma-v300-classes
```

## Usage
- Interactive mode:
```bash
python enigma_v300_classes.py --verbose
```
- Command-line examples:
```bash
python enigma_v300_classes.py -n 0003333016 4 --logfile enigma.log
python enigma_v300_classes.py -e 0000607 7 6963
```

## Test Cases
**NetTool:**
```bash
python enigma_v300_classes.py -n 0003333016 4
```
Output: Option Key: 5dab ade1 12dd

**EtherScope:**
```bash
python enigma_v300_classes.py -e 0000607 7 6963
```
Output: Option Key: 6406 2579 4859 7747

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for fork-branch-PR guidelines.

## License
MIT License. See [LICENSE](LICENSE) for details.