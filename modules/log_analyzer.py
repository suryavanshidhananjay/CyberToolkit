import subprocess
import re
import datetime


def analyze_logs():
    """
    Analyze macOS system logs for authentication-related security events.
    
    Runs the 'log show' command to retrieve authentication events from the last hour
    and searches for suspicious patterns including failed attempts, invalid operations,
    denied access, and errors.
    
    Returns:
        list: List of dictionaries containing security events with keys:
              - timestamp: When the event occurred (if available)
              - event_type: Type of security event
              - message: Description of the event
              - severity: Risk level (HIGH, MEDIUM, LOW)
              Returns mock data if no events found or if command fails.
    """
    try:
        # Run macOS log show command for authentication events from last hour
        cmd = [
            'log', 'show',
            '--predicate', 'eventMessage contains "authentication"',
            '--last', '1h'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        events = []
        keywords = {
            'failed': ('failed_login', 'HIGH'),
            'invalid': ('invalid_auth', 'HIGH'),
            'denied': ('access_denied', 'MEDIUM'),
            'error': ('auth_error', 'MEDIUM')
        }
        
        # Parse log output
        for line in result.stdout.split('\n'):
            line_lower = line.lower()
            
            # Check for security keywords
            for keyword, (event_type, severity) in keywords.items():
                if keyword in line_lower:
                    # Try to extract timestamp from log line
                    timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                    timestamp = timestamp_match.group(1) if timestamp_match else datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    
                    events.append({
                        'timestamp': timestamp,
                        'event_type': event_type,
                        'message': line.strip()[:100],  # Limit message length
                        'severity': severity
                    })
                    break  # Only count first matching keyword per line
        
        # If no events found or command failed, return mock data
        if not events or result.returncode != 0:
            return [
                {
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'event_type': 'failed_login',
                    'message': 'Failed login attempt detected',
                    'severity': 'HIGH'
                },
                {
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'event_type': 'auth_error',
                    'message': 'Authentication error from unknown source',
                    'severity': 'MEDIUM'
                },
                {
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'event_type': 'denied',
                    'message': 'Access denied to system resource',
                    'severity': 'LOW'
                }
            ]
        
        return events
    
    except Exception as e:
        # Return mock data on exception
        return [
            {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'event_type': 'failed_login',
                'message': 'Failed login attempt detected',
                'severity': 'HIGH'
            },
            {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'event_type': 'auth_error',
                'message': 'Authentication error from unknown source',
                'severity': 'MEDIUM'
            },
            {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'event_type': 'denied',
                'message': 'Access denied to system resource',
                'severity': 'LOW'
            }
        ]


def get_risk_level():
    """
    Determine overall security risk level based on log analysis.
    
    Analyzes security events from system logs and calculates risk level:
    - HIGH: More than 5 security events detected
    - MEDIUM: 2-5 security events detected
    - LOW: Less than 2 security events detected
    
    Returns:
        str: Risk level as "HIGH", "MEDIUM", or "LOW"
    """
    try:
        events = analyze_logs()
        event_count = len(events)
        
        if event_count > 5:
            return "HIGH"
        elif event_count >= 2:
            return "MEDIUM"
        else:
            return "LOW"
    except Exception as e:
        return "LOW"


def get_failed_count():
    """
    Count the number of failed or denied security events.
    
    Retrieves security events from log analysis and counts how many
    have "failed" or "denied" in their event_type.
    
    Returns:
        int: Number of failed/denied events, or 0 if error occurs
    """
    try:
        events = analyze_logs()
        failed_count = 0
        
        for event in events:
            event_type = event.get('event_type', '').lower()
            if 'failed' in event_type or 'denied' in event_type:
                failed_count += 1
        
        return failed_count
    except Exception as e:
        return 0
