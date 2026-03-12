"""
Process Monitor Module
Monitors running processes and system statistics for security analysis on macOS
"""

import psutil
from datetime import datetime


def get_all_processes():
    """
    Get all running processes with their details.
    
    Returns:
        list: List of process dictionaries sorted by CPU usage (descending).
              Each dict contains: pid, name, cpu_percent, memory_percent,
              status, username, exe
    """
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'status', 'username']):
        try:
            # Get basic info
            pid = proc.info['pid']
            name = proc.info['name']
            status = proc.info['status']
            username = proc.info['username']
            
            # Get CPU and memory (may raise exceptions)
            try:
                cpu_percent = proc.cpu_percent(interval=0.1)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cpu_percent = 0.0
            
            try:
                memory_percent = proc.memory_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                memory_percent = 0.0
            
            # Get executable path
            try:
                exe = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                exe = ""
            
            process_data = {
                'pid': pid,
                'name': name,
                'cpu_percent': round(cpu_percent, 2),
                'memory_percent': round(memory_percent, 2),
                'status': status,
                'username': username if username else "unknown",
                'exe': exe
            }
            
            processes.append(process_data)
            
        except psutil.NoSuchProcess:
            # Process terminated during iteration
            continue
        except psutil.AccessDenied:
            # No permission to access this process
            continue
        except Exception:
            # Handle any other unexpected errors
            continue
    
    # Sort by CPU usage (descending)
    processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
    
    return processes


def get_suspicious_processes():
    """
    Identify potentially suspicious processes based on various criteria.
    
    A process is flagged as suspicious if:
    - CPU usage > 80%
    - Executable path contains "tmp" or "temp" or is empty
    - Process name length > 20 characters
    
    Returns:
        list: List of suspicious process dictionaries.
              Each dict contains: pid, name, cpu_percent, reason
    """
    suspicious = []
    
    try:
        all_processes = get_all_processes()
        
        for proc in all_processes:
            reasons = []
            
            # Check 1: High CPU usage
            if proc['cpu_percent'] > 80:
                reasons.append(f"High CPU usage ({proc['cpu_percent']}%)")
            
            # Check 2: Suspicious executable path
            exe_path = proc['exe'].lower()
            
            if not exe_path:
                reasons.append("No executable path")
            elif 'tmp' in exe_path or 'temp' in exe_path:
                reasons.append("Executable in tmp/temp directory")
            
            # Check 3: Long process name (possible obfuscation)
            if len(proc['name']) > 20:
                reasons.append(f"Suspicious name length ({len(proc['name'])} chars)")
            
            # If any suspicious criteria met, add to list
            if reasons:
                suspicious_proc = {
                    'pid': proc['pid'],
                    'name': proc['name'],
                    'cpu_percent': proc['cpu_percent'],
                    'reason': '; '.join(reasons)
                }
                suspicious.append(suspicious_proc)
        
    except Exception:
        return []
    
    return suspicious


def get_system_stats():
    """
    Get overall system statistics including CPU, memory, disk, and uptime.
    
    Returns:
        dict: System statistics including:
            - total_cpu: Overall CPU usage percentage
            - total_memory: Dict with total, available, percent
            - disk_usage: Dict with total, used, free, percent for root path
            - boot_time: Formatted datetime string of system boot time
    """
    try:
        # CPU statistics
        total_cpu = psutil.cpu_percent(interval=1)
        
        # Memory statistics
        memory = psutil.virtual_memory()
        total_memory = {
            'total': memory.total,
            'available': memory.available,
            'percent': round(memory.percent, 2)
        }
        
        # Disk statistics (root path)
        disk = psutil.disk_usage('/')
        disk_usage = {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': round(disk.percent, 2)
        }
        
        # Boot time
        boot_timestamp = psutil.boot_time()
        boot_datetime = datetime.fromtimestamp(boot_timestamp)
        boot_time = boot_datetime.strftime('%Y-%m-%d %H:%M:%S')
        
        return {
            'total_cpu': round(total_cpu, 2),
            'total_memory': total_memory,
            'disk_usage': disk_usage,
            'boot_time': boot_time
        }
        
    except Exception:
        return {
            'total_cpu': 0,
            'total_memory': {
                'total': 0,
                'available': 0,
                'percent': 0
            },
            'disk_usage': {
                'total': 0,
                'used': 0,
                'free': 0,
                'percent': 0
            },
            'boot_time': 'Unknown'
        }
