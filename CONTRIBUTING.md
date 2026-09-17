# Contributing to Practical Network Security Lab

Thank you for taking the time to contribute. This project is built around quality over quantity — every addition should make the lab more useful, more accurate, or easier to use.

---

## Ways to contribute

### 1. Fix an error or improve a module
If a command is wrong, an explanation is unclear, or a defensive step is missing:
- Open an issue using the **Module Feedback** template
- Or open a PR directly against the module's `README.md`, `commands.md`, or `attack_analysis.md`

### 2. Add a detection script
New scripts go in `scripts/`. Follow the existing style:
- Python 3.7+, stdlib only (scapy is allowed)
- `argparse` for all arguments — no hardcoded values
- Colour output via ANSI codes, disabled when stdout is not a tty
- A docstring at the top with: purpose, usage examples, required packages
- Comments on every non-obvious block
- A `main()` function with `if __name__ == "__main__": main()`

### 3. Improve a sample PCAP
If you can generate a more realistic or richer synthetic capture for any of the 11 samples, open a PR with:
- The new `.pcap` file in `samples/`
- An update to `samples/README.md` describing what's in it
- The script or commands used to generate it (so it's reproducible)

### 4. Add a new module
If you want to add a topic not currently covered (e.g., BGP hijacking, Wi-Fi attacks, VLAN hopping):
- Open an issue first to discuss scope and placement
- Follow the three-file structure: `README.md`, `commands.md`, `attack_analysis.md`
- Include both offensive flow and defensive detection in `README.md`
- Add a lab exercise with clear pass/fail criteria

---

## Pull Request guidelines

- **One PR per change** — don't bundle unrelated fixes
- **Test every command** you add in an actual lab VM before submitting
- **No real IPs or credentials** — use only `192.168.56.x` lab addresses
- **Keep the safety framing** — every offensive exercise must note it runs only in an isolated lab
- **Match the existing tone** — factual, direct, no hype

---

## Setting up the lab to test your changes

```bash
# Clone the repo
git clone https://github.com/imranshaikh116/Practical-Network-Security-Lab.git
cd Practical-Network-Security-Lab

# Set up your VMs per LAB_RANGE_SETUP.md
# Kali: 192.168.56.10
# Target: 192.168.56.20

# Install script dependencies
pip install scapy

# Test a script change
sudo python3 scripts/arp_monitor.py --iface eth0 --interval 2
```

---

## Testing detection scripts

Before submitting a script change:

```bash
# Syntax check
python3 -m py_compile scripts/your_script.py

# Run with --help to verify argument parsing
python3 scripts/your_script.py --help

# Test against a sample pcap where applicable
python3 scripts/pcap_summary.py samples/01_arp_traffic_sample.pcap
```

---

## Coding style for scripts

```python
# Good: argparse, docstring, main(), ANSI only when tty
#!/usr/bin/env python3
"""
script_name.py
--------------
One line summary.

Usage
-----
    python3 script_name.py --option value

Requires
--------
    Python 3.7+  scapy (pip install scapy)
"""

import argparse
import sys

RESET = "\033[0m"
GREEN = "\033[92m"

def c(text, colour):
    return f"{colour}{text}{RESET}" if sys.stdout.isatty() else text

def main():
    parser = argparse.ArgumentParser(description="...")
    parser.add_argument("--option", default="value", help="...")
    args = parser.parse_args()
    # logic here

if __name__ == "__main__":
    main()
```

---

## Reporting bugs

Use the **Module Feedback** issue template and fill in:
- Which module (`05_mitm`, `scripts/arp_monitor.py`, etc.)
- What's wrong or unclear
- Your suggested fix (if you have one)

---

## Code of conduct

This is an educational security project. Contributions must:
- Stay within the scope of isolated lab learning
- Not add working exploit code targeting real systems
- Not include credentials, real IPs, or personal data
- Be respectful and constructive in all discussions

---

Thank you for helping make this better.
