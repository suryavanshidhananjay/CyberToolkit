import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict
import re

def analyze_logs():
    """
    Analyzes Windows Security Event Logs for suspicious login activity.
    Returns a list of dictionaries containing suspicious events.
    """
    findings = []

    try:
        # Export recent security events to XML using wevtutil
        cmd = [
            'wevtutil', 'qe', 'Security',
            '/q:*[System[(EventID=4624 or EventID=4625)]]',
            '/f:XML',
            '/c:1000'  # Limit to last 1000 events
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        xml_content = result.stdout

        if not xml_content.strip():
            print("No security events found or access denied. Try running as Administrator.")
            return findings

        # Parse XML and extract events
        events = parse_event_xml(xml_content)

        # Analyze events for suspicious activity
        findings = analyze_events(events)

    except subprocess.CalledProcessError as e:
        print(f"Error running wevtutil: {e}")
        print("Make sure you're running as Administrator or have appropriate permissions.")
    except Exception as e:
        print(f"Unexpected error: {e}")

    return findings

def parse_event_xml(xml_content):
    """
    Parses XML output from wevtutil and extracts relevant login events.
    """
    events = []
    root = ET.fromstring(f'<Events>{xml_content}</Events>')

    for event in root:
        try:
            event_id = None
            timestamp = None
            username = None
            ip_address = None

            # Get event ID
            event_id_elem = event.find('.//EventID')
            if event_id_elem is not None:
                event_id = int(event_id_elem.text)

            # Get timestamp
            time_elem = event.find('.//TimeCreated')
            if time_elem is not None:
                timestamp_str = time_elem.get('SystemTime')
                if timestamp_str:
                    # Parse ISO format timestamp
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))

            # Get username and IP for login events
            if event_id in [4624, 4625]:
                # Extract data from EventData
                event_data = event.find('.//EventData')
                if event_data is not None:
                    data_items = event_data.findall('Data')

                    for i, data in enumerate(data_items):
                        if data.get('Name') == 'TargetUserName':
                            username = data.text
                        elif data.get('Name') == 'IpAddress':
                            ip_address = data.text

                # If username not found in standard location, try alternative parsing
                if not username:
                    # Look for username in the event data (different positions for different event types)
                    for data in data_items:
                        text = data.text
                        if text and '\\' in text and len(text.split('\\')) == 2:
                            username = text.split('\\')[1]
                            break

                events.append({
                    'event_id': event_id,
                    'timestamp': timestamp,
                    'username': username or 'Unknown',
                    'ip_address': ip_address or 'Local',
                    'event_type': 'success' if event_id == 4624 else 'failure'
                })

        except Exception as e:
            print(f"Error parsing event: {e}")
            continue

    return events

def analyze_events(events):
    """
    Analyzes parsed events to identify suspicious activity.
    """
    findings = []
    failed_attempts = defaultdict(int)
    recent_events = []

    # Sort events by timestamp (most recent first)
    events.sort(key=lambda x: x['timestamp'] or datetime.min, reverse=True)

    # Count failed attempts per username
    for event in events:
        if event['event_type'] == 'failure':
            failed_attempts[event['username']] += 1

    # Analyze each event
    for event in events:
        risk_level = get_risk_level(event['username'], failed_attempts[event['username']])

        # Include all events, but flag suspicious ones
        finding = {
            'timestamp': event['timestamp'].isoformat() if event['timestamp'] else 'Unknown',
            'event_type': event['event_type'],
            'username': event['username'],
            'ip_address': event['ip_address'],
            'risk_level': risk_level,
            'failed_attempts': failed_attempts[event['username']] if event['event_type'] == 'failure' else 0
        }

        # Only include events that might be suspicious
        if (event['event_type'] == 'failure' or
            (event['event_type'] == 'success' and event['ip_address'] != 'Local')):
            findings.append(finding)

    return findings

def get_risk_level(username, failed_attempts):
    """
    Determines the risk level based on failed login attempts.
    Returns LOW, MEDIUM, or HIGH.
    """
    if failed_attempts > 10:
        return 'HIGH'
    elif failed_attempts > 3:
        return 'MEDIUM'
    else:
        return 'LOW'

if __name__ == "__main__":
    findings = analyze_logs()

    if not findings:
        print("No suspicious login events found.")
    else:
        print(f"Found {len(findings)} suspicious events:")
        print("-" * 80)

        for finding in findings:
            print(f"Time: {finding['timestamp']}")
            print(f"Type: {finding['event_type'].title()} Login")
            print(f"User: {finding['username']}")
            print(f"IP: {finding['ip_address']}")
            print(f"Risk: {finding['risk_level']}")
            if finding['failed_attempts'] > 0:
                print(f"Failed Attempts: {finding['failed_attempts']}")
            print("-" * 40)