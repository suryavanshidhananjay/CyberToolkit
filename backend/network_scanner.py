"""
Network Scanner Module
Scans local network for devices on macOS
"""

import subprocess
import socket
import re


def scan_network():
    """
    Scan the local network for devices using ARP table.
    
    Uses the 'arp -a' command on macOS to retrieve devices from the ARP cache.
    Works without root/admin privileges.
    
    Returns:
        list: List of device dictionaries. Each dict contains:
              - ip: IP address
              - mac: MAC address
              - hostname: Hostname (if available, otherwise "Unknown")
    """
    devices = []
    
    try:
        # Run arp -a command on macOS
        result = subprocess.run(
            ['arp', '-a'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            print(f"ARP command failed with return code {result.returncode}")
            return []
        
        output = result.stdout
        
        # Parse each line of arp output
        # Expected format: hostname (ip) at mac on interface
        # Example: router.local (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
        
        for line in output.split('\n'):
            if not line.strip():
                continue
            
            # Extract IP address (in parentheses)
            ip_match = re.search(r'\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)', line)
            
            # Extract MAC address (xx:xx:xx:xx:xx:xx format)
            mac_match = re.search(r'at ([0-9a-fA-F:]+)', line)
            
            # Extract hostname (before the IP address in parentheses)
            hostname_match = re.search(r'^([^\s]+)\s+\(', line)
            
            # Only add if we have both IP and MAC
            if ip_match and mac_match:
                ip = ip_match.group(1)
                mac = mac_match.group(1)
                hostname = hostname_match.group(1) if hostname_match else "Unknown"
                
                # Filter out incomplete entries (e.g., incomplete MACs)
                if mac.lower() == '(incomplete)':
                    continue
                
                # Validate MAC address format
                if not re.match(r'^([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}$', mac):
                    continue
                
                device = {
                    'ip': ip,
                    'mac': mac.lower(),  # Normalize to lowercase
                    'hostname': hostname
                }
                
                devices.append(device)
        
    except subprocess.TimeoutExpired:
        print("ARP command timed out")
        return []
    except FileNotFoundError:
        print("ARP command not found")
        return []
    except Exception as e:
        print(f"Error scanning network: {e}")
        return []
    
    return devices


def get_local_ip():
    """
    Get the local machine's IP address.
    
    Uses socket library to determine the primary IP address of the local machine.
    Works without root/admin privileges.
    
    Returns:
        str: Local IP address or "unknown" if unable to determine
    """
    try:
        # Create a socket connection to determine local IP
        # This doesn't actually send data, just determines routing
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Connect to a public DNS server (doesn't actually send packets)
        s.connect(("8.8.8.8", 80))
        
        # Get the local IP address used for the connection
        local_ip = s.getsockname()[0]
        
        s.close()
        
        return local_ip
        
    except Exception:
        # Fallback method: get hostname and resolve it
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            return local_ip
        except Exception:
            return "unknown"
