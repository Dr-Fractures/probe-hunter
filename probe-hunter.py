#!/usr/bin/env python3
import signal
import sys
import subprocess
import re
from datetime import datetime
from scapy.all import sniff, Dot11, Dot11ProbeReq
from pyfiglet import Figlet
from rich.console import Console
from rich.text import Text
from rich.prompt import IntPrompt
from mac_vendor_lookup import MacLookup

# --- Configuration ---
console = Console()
mac_lookup = MacLookup()
vendor_cache = {}
INTERFACE = None
MONITOR_METHOD = "iw"  # "iw" or "airmon" — tracks how monitor mode was enabled so we can cleanly revert it

def show_banner():
    f = Figlet(font='slant')
    console.print(f"[bold cyan]{f.renderText('Probe Hunter')}[/bold cyan]")
    console.print("[bold yellow]Wi-Fi Probe Request Sniffer[/bold yellow]\n")

def get_wireless_interfaces():
    """Detect wireless interfaces using 'iw dev'."""
    interfaces = []
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        for line in lines:
            if line.strip().startswith("Interface"):
                iface = line.split()[1]
                interfaces.append(iface)
    except Exception:
        pass
    return interfaces

def enable_monitor_mode(iface):
    """Enable monitor mode using 'iw' to avoid killing SSH connections if possible.

    Returns (monitor_iface_name, method) where method is 'iw' or 'airmon'.
    """
    console.print(f"[dim]Attempting to enable monitor mode on {iface} using 'iw'...[/dim]")
    console.print("[yellow]Note: If this fails, you may still need to stop NetworkManager manually.[/yellow]")

    # 1. Bring interface down
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"], capture_output=True)

    # 2. Set monitor mode.
    #    BUG FIX: the old code ran `iw <iface> set monitor none`, which is not valid
    #    syntax for switching an interface *into* monitor mode — "set monitor <flags>"
    #    only works on an interface that is already type monitor. The correct command
    #    to change the interface type is `iw <iface> set type monitor`.
    result = subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "monitor"], capture_output=True, text=True)

    if result.returncode != 0:
        console.print(f"[bold red]Failed to set monitor mode with 'iw'.[/bold red]")
        console.print(result.stderr)
        console.print("[yellow]Falling back to airmon-ng (this WILL kill SSH if on Wi-Fi)...[/yellow]")

        # BUG FIX: the old regex tried to parse airmon-ng's text output
        # ("...enabled on [phy0]wlan0mon") but `(\w+)` can't match past the
        # leading '[' in "[phy0]wlan0mon", so it never matched on modern
        # airmon-ng versions and silently fell back to a guessed name.
        # Diffing `iw dev` before/after is far more reliable.
        before = set(get_wireless_interfaces())
        subprocess.run(["sudo", "airmon-ng", "check", "kill"], capture_output=True)
        subprocess.run(["sudo", "airmon-ng", "start", iface], capture_output=True, text=True)
        after = set(get_wireless_interfaces())
        new_ifaces = after - before

        if new_ifaces:
            return new_ifaces.pop(), "airmon"
        if iface in after:
            # Some drivers keep the same interface name and just flip its type
            return iface, "airmon"
        # Last resort guess, same as original behavior
        return f"{iface}mon", "airmon"

    # 3. Bring interface up
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"], capture_output=True)

    # 4. Verify and return name (stays the same with iw, unlike airmon-ng which adds 'mon')
    result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
    if iface in result.stdout:
        return iface, "iw"

    # Fallback if name changed unexpectedly
    return f"{iface}mon", "iw"

def stop_monitor_mode(iface, method="iw"):
    """Stop monitor mode on exit, using whichever method actually enabled it."""
    if not iface:
        return
    console.print(f"\n[dim]Stopping monitor mode on {iface}...[/dim]")
    if method == "airmon":
        subprocess.run(["sudo", "airmon-ng", "stop", iface], capture_output=True, text=True)
    else:
        # BUG FIX: the old code always called `airmon-ng stop`, even when monitor
        # mode had been enabled via 'iw'. Since 'iw' never created a *mon interface,
        # that call was a no-op that left the interface stuck in monitor mode.
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"], capture_output=True)
        subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "managed"], capture_output=True)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"], capture_output=True)

def signal_handler(sig, frame):
    console.print("\n[bold red]⚠ Scan Stopped.[/bold red]")
    stop_monitor_mode(INTERFACE, MONITOR_METHOD)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def get_vendor(mac):
    if mac in vendor_cache:
        return vendor_cache[mac]
    try:
        vendor = mac_lookup.lookup(mac)
        vendor_cache[mac] = vendor
        return vendor
    except Exception:
        return "Unknown"

def process_packet(packet):
    if packet.haslayer(Dot11ProbeReq):
        mac = packet.addr2
        ssid = ""
        try:
            ssid = packet[Dot11].info.decode('utf-8', errors='ignore').strip()
        except Exception:
            pass

        if not ssid:
            return

        timestamp = datetime.now().strftime("%H:%M:%S")
        vendor = get_vendor(mac)

        text = Text()
        text.append(f"[{timestamp}] ", style="dim")
        text.append(f"{mac} ", style="bold magenta")
        text.append(f"({vendor}) ", style="cyan")
        text.append("-> ", style="white")
        text.append("Probing: ", style="dim white")
        text.append(f"{ssid}", style="bold green")

        console.print(text)

if __name__ == "__main__":
    show_banner()

    interfaces = get_wireless_interfaces()

    if not interfaces:
        console.print("[bold red]No wireless interfaces found.[/bold red]")
        console.print("[yellow]Hint: Ensure you are not in a VM and your adapter is connected.[/yellow]")
        sys.exit(1)

    console.print("[bold blue]Available Wireless Adapters:[/bold blue]")
    for i, iface in enumerate(interfaces):
        console.print(f"  [{i+1}] {iface}")

    selected_iface = None
    while True:
        try:
            choice = IntPrompt.ask("\n[bold green]Select adapter number", choices=[str(i) for i in range(1, len(interfaces)+1)])
            selected_iface = interfaces[choice - 1]
            break
        except Exception:
            console.print("[bold red]Invalid selection. Try again.[/bold red]")

    monitor_iface, MONITOR_METHOD = enable_monitor_mode(selected_iface)
    INTERFACE = monitor_iface

    result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
    if monitor_iface not in result.stdout:
        console.print(f"[bold red]Critical Error: Interface '{monitor_iface}' was not created![/bold red]")
        console.print("Your code logic found a name, but the system does not see the device.")
        console.print("Try running `sudo airmon-ng start " + selected_iface + "` manually to debug.")
        stop_monitor_mode(monitor_iface, MONITOR_METHOD)
        sys.exit(1)

    console.print(f"[bold green]✓ Monitor mode enabled on {monitor_iface}[/bold green]\n")

    try:
        console.print("[dim]Updating MAC vendor database...[/dim]")
        mac_lookup.update_vendors()
    except:
        pass

    try:
        console.print(f"[dim]Listening on {INTERFACE}... Press Ctrl+C to stop.[/dim]\n")
        sniff(iface=INTERFACE, prn=process_packet, store=0)
    except Exception as e:
        console.print(f"[bold red]Sniff Error: {e}[/bold red]")
        stop_monitor_mode(INTERFACE, MONITOR_METHOD)
        sys.exit(1)
