import subprocess
import socket
import ipaddress
import re

def scan_network():
    """
    Scans the local network (192.168.1.0/24) for connected devices.
    Returns a list of dictionaries with keys: ip, mac, hostname.
    """
    network = ipaddress.ip_network('192.168.1.0/24')
    devices = []

    # First, ping all hosts to populate ARP cache
    print("Pinging network to populate ARP cache...")
    for ip in network.hosts():
        try:
            subprocess.run(['ping', '-n', '1', '-w', '100', str(ip)], 
                         capture_output=True, check=False)
        except Exception as e:
            print(f"Error pinging {ip}: {e}")

    # Now, get ARP table
    print("Retrieving ARP table...")
    try:
        arp_result = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=True)
        arp_lines = arp_result.stdout.split('\n')
    except subprocess.CalledProcessError as e:
        print(f"Error running arp command: {e}")
        return devices
    except Exception as e:
        print(f"Unexpected error: {e}")
        return devices

    # Parse ARP table
    ip_mac = {}
    for line in arp_lines:
        # Match lines like: 192.168.1.1           00-11-22-33-44-55     dynamic
        match = re.match(r'\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s+', line, re.IGNORECASE)
        if match:
            ip = match.group(1)
            mac = match.group(2).upper()
            if ip.startswith('192.168.1.'):
                ip_mac[ip] = mac

    # Get hostnames and build device list
    for ip, mac in ip_mac.items():
        hostname = get_hostname(ip)
        devices.append({
            'ip': ip,
            'mac': mac,
            'hostname': hostname
        })

    return devices

def get_hostname(ip):
    """
    Resolves hostname for an IP address.
    Returns hostname or None if resolution fails.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return None
    except Exception as e:
        print(f"Error resolving hostname for {ip}: {e}")
        return None

if __name__ == "__main__":
    devices = scan_network()
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname'] or 'Unknown'}")