# probe-hunter

# probe-hunter

Wi-Fi probe request sniffer. Puts a wireless adapter into monitor mode and
listens for 802.11 probe requests, resolving the source MAC to a vendor and
printing each probe (MAC, vendor, and requested SSID) live to the terminal.

Part of a small wireless recon toolkit (alongside `doubletap`, `wifi-scan`,
and `wifi-sniff`) — Bash/Python scripts wrapping the aircrack-ng suite,
symlinked into `/usr/local/bin/` for system-wide use.

## Features

- Auto-detects available wireless interfaces via `iw dev`
- Interactive adapter selection
- Enables monitor mode via `iw` first, falling back to `airmon-ng` if needed
- Live MAC vendor lookups (via `mac-vendor-lookup`) with local caching
- Clean, color-coded output via `rich`
- Graceful cleanup on Ctrl+C (stops monitor mode before exiting)

## Requirements

- Kali Linux (or another distro with `aircrack-ng` / `iw` installed)
- A wireless adapter capable of monitor mode
- Python 3
- `sudo` privileges (monitor mode requires root)

## Installation

```bash
git clone https://github.com/AmpedGH/probe-hunter.git
cd probe-hunter
chmod +x install.sh
./install.sh
```

This installs the Python dependencies and symlinks `probe-hunter.py` to
`/usr/local/bin/probe-hunter`.

## Usage

```bash
sudo probe-hunter
```

Select your wireless adapter from the numbered list when prompted. The tool
enables monitor mode and starts printing probe requests as they're seen.
Press `Ctrl+C` to stop — monitor mode is automatically disabled on exit.

## Uninstall

```bash
sudo rm /usr/local/bin/probe-hunter
```

## Disclaimer

For authorized security research and educational use only. Only run this
against networks and devices you own or have explicit permission to test.
