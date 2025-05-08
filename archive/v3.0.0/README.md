# Enigma v3.0.0 - Python Classes Implementation

## Overview
This is a Python implementation of the Fluke option key calculator using an object-oriented design with classes (EnigmaC, Enigma2C, EnigmaMenu). It generates and validates option keys for Fluke network testing devices using EnigmaC (NetTool, 10-digit serial) and Enigma2C (other products, 7-digit serial) ciphers.

- **Author**: Kris Armstrong
- **Version**: 3.0.0
- **License**: MIT

## Features
- Generates option keys for NetTool (10-digit serial) and other Fluke products (7-digit serial).
- Validates option keys against serial numbers and options.
- Interactive menu with product and option selection.
- Command-line support for automation.

## Requirements
- Python 3.6+

## Usage

- Interactive mode:

  ```bash
  python enigma_v300_classes.py 
  ```

- Command-Line examples:

  ```bash
  python enigma_v300_classes.py -n 0003333016 4  # NetTool key
  python enigma_v300_classes.py -e 0000607 7 6963  # EtherScope key
  ```

## Test Cases

**NetTool:**

  ```bash
   python enigma_v300_classes.py -n 0003333016 4
  ```

- Output: Option Key: 5dab ade1 12dd

**EtherScope:**

```bash
  python enigma_v300_classes.py -e 0000607 7 6963
```

- Output: Option Key: 6406 2579 4859 7747

## License

This software is licensed under the MIT License. See the LICENSE file for details.
python enigma_v200_classes.py