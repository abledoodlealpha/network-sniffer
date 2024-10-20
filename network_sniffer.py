import os
import sys
from scapy.all import sniff

# Function to process each captured packet
def packet_callback(packet):
    """
    This function is called for each packet captured by the sniffer.
    It prints a summary of the packet.
    """
    print("Captured Packet:")
    print(packet.summary())
    print("-" * 50)  # Separator to make the output easier to read

# Function to check if the script is run as root/admin
def check_root_privileges():
    """
    Ensure the script is run with the necessary privileges.
    Packet sniffing requires administrative access.
    """
    if os.geteuid() != 0:  # Check if not running as root
        print("Error: This script needs to be run with root privileges.")
        print("Try running the script with 'sudo' (Linux/macOS).")
        sys.exit(1)  # Exit the script if not running as root

# Function to start the packet sniffer
def start_sniffer(interface=None):
    """
    Start the sniffer on the specified network interface.

    Args:
        interface (str): The network interface to sniff on (e.g., "eth0", "wlan0").
                         If None, the default interface will be used.
    """
    print(f"Starting sniffer on interface: {interface if interface else 'default'}")
    
    try:
        # Start sniffing packets and call packet_callback for each packet captured
        sniff(iface=interface, prn=packet_callback, store=0)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)  # Exit the script on any error

# Main function where execution begins
if __name__ == "__main__":
    # Step 1: Check if the script is run as root
    check_root_privileges()

    # Step 2: Define the network interface to sniff on
    # Leave this as None to use the default network interface (like "eth0" or "wlan0")
    network_interface = None  # Change this to specify an interface, e.g., "eth0" for Ethernet

    # Step 3: Start the sniffer
    start_sniffer(network_interface)

