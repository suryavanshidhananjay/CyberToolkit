from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import psutil
import os
import json
from datetime import datetime
import threading
import time

# Import our custom modules
from modules.network_scanner import scan_network
from modules.log_analyzer import analyze_logs
from modules.password_checker import check_password_strength
from modules.file_integrity import FileIntegrityMonitor

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global variables for monitoring
file_monitor = None
alerts = []

@app.route('/')
def dashboard():
    """Serve the main dashboard HTML page"""
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Personal Cybersecurity Toolkit</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { text-align: center; margin-bottom: 30px; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
            .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .metric { text-align: center; margin: 10px 0; }
            .metric-value { font-size: 2em; font-weight: bold; color: #007bff; }
            .alert { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 4px; }
            .alert-high { background: #f8d7da; border-color: #f5c6cb; }
            button { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
            button:hover { background: #0056b3; }
            input { padding: 8px; margin: 5px; border: 1px solid #ddd; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Personal Cybersecurity Toolkit</h1>
                <p>Monitor your system's security status</p>
            </div>

            <div class="grid">
                <div class="card">
                    <h3>System Health Score</h3>
                    <div class="metric">
                        <div class="metric-value" id="health-score">--</div>
                        <div>/100</div>
                    </div>
                    <button onclick="updateHealthScore()">Refresh</button>
                </div>

                <div class="card">
                    <h3>Running Processes</h3>
                    <div id="process-count">-- processes</div>
                    <button onclick="loadProcesses()">View Processes</button>
                </div>

                <div class="card">
                    <h3>Network Devices</h3>
                    <div id="network-count">-- devices</div>
                    <button onclick="loadNetwork()">Scan Network</button>
                </div>

                <div class="card">
                    <h3>Security Logs</h3>
                    <div id="log-count">-- events</div>
                    <button onclick="loadLogs()">Check Logs</button>
                </div>

                <div class="card">
                    <h3>Password Strength</h3>
                    <input type="password" id="password-input" placeholder="Enter password">
                    <button onclick="checkPassword()">Check Strength</button>
                    <div id="password-result"></div>
                </div>

                <div class="card">
                    <h3>File Integrity Monitor</h3>
                    <input type="text" id="folder-path" placeholder="Enter folder path">
                    <button onclick="startMonitoring()">Start Monitoring</button>
                </div>
            </div>

            <div class="card">
                <h3>Security Alerts</h3>
                <div id="alerts-container">No alerts</div>
                <button onclick="loadAlerts()">Refresh Alerts</button>
            </div>
        </div>

        <script>
            async function updateHealthScore() {
                try {
                    const response = await fetch('/api/health_score');
                    const data = await response.json();
                    document.getElementById('health-score').textContent = data.score;
                } catch (error) {
                    console.error('Error:', error);
                }
            }

            async function loadProcesses() {
                try {
                    const response = await fetch('/api/processes');
                    const data = await response.json();
                    document.getElementById('process-count').textContent = data.length + ' processes';
                    console.log('Processes:', data);
                } catch (error) {
                    console.error('Error:', error);
                }
            }

            async function loadNetwork() {
                try {
                    const response = await fetch('/api/network');
                    const data = await response.json();
                    document.getElementById('network-count').textContent = data.length + ' devices';
                    console.log('Network devices:', data);
                } catch (error) {
                    console.error('Error:', error);
                }
            }

            async function loadLogs() {
                try {
                    const response = await fetch('/api/logs');
                    const data = await response.json();
                    document.getElementById('log-count').textContent = data.length + ' events';
                    console.log('Security logs:', data);
                } catch (error) {
                    console.error('Error:', error);
                }
            }

            async function checkPassword() {
                const password = document.getElementById('password-input').value;
                try {
                    const response = await fetch('/api/check_password', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password: password })
                    });
                    const data = await response.json();
                    document.getElementById('password-result').innerHTML = `
                        <strong>Strength:</strong> ${data.strength}<br>
                        <strong>Score:</strong> ${data.score}/100<br>
                        <strong>Feedback:</strong> ${data.feedback.join(', ')}
                    `;
                } catch (error) {
                    console.error('Error:', error);
                }
            }

            async function startMonitoring() {
                const path = document.getElementById('folder-path').value;
                try {
                    const response = await fetch('/api/start_monitor', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ path: path })
                    });
                    const data = await response.json();
                    alert(data.message);
                } catch (error) {
                    console.error('Error:', error);
                }
            }

            async function loadAlerts() {
                try {
                    const response = await fetch('/api/alerts');
                    const data = await response.json();
                    const container = document.getElementById('alerts-container');
                    if (data.length === 0) {
                        container.innerHTML = 'No alerts';
                    } else {
                        container.innerHTML = data.map(alert =>
                            `<div class="alert ${alert.level === 'HIGH' ? 'alert-high' : ''}">
                                <strong>${alert.level}:</strong> ${alert.message}<br>
                                <small>${alert.timestamp}</small>
                            </div>`
                        ).join('');
                    }
                } catch (error) {
                    console.error('Error:', error);
                }
            }

            // Load initial data
            updateHealthScore();
            loadAlerts();
        </script>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/api/processes')
def get_processes():
    """Get list of running processes"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                processes.append({
                    'name': info['name'] or 'Unknown',
                    'pid': info['pid'],
                    'cpu_percent': round(info['cpu_percent'] or 0, 2),
                    'memory_percent': round(info['memory_percent'] or 0, 2)
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Sort by CPU usage descending
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        return jsonify(processes[:50])  # Return top 50 processes
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/network')
def get_network():
    """Get list of connected network devices"""
    try:
        devices = scan_network()
        return jsonify(devices)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def get_logs():
    """Get suspicious login events from Windows event logs"""
    try:
        events = analyze_logs()
        return jsonify(events)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health_score')
def get_health_score():
    """Calculate and return system health score (0-100)"""
    try:
        score = 100
        issues = []

        # Check CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > 80:
            score -= 20
            issues.append("High CPU usage")

        # Check memory usage
        memory = psutil.virtual_memory()
        if memory.percent > 80:
            score -= 20
            issues.append("High memory usage")

        # Check disk usage
        disk = psutil.disk_usage('/')
        if disk.percent > 90:
            score -= 15
            issues.append("Low disk space")

        # Check network connections
        connections = psutil.net_connections()
        suspicious_ports = [21, 22, 23, 25, 53, 80, 443, 3389]  # Common ports
        open_ports = set()
        for conn in connections:
            if conn.status == 'LISTEN' and conn.laddr:
                port = conn.laddr.port
                if port in suspicious_ports:
                    open_ports.add(port)

        if open_ports:
            score -= 10
            issues.append(f"Open ports: {', '.join(map(str, open_ports))}")

        # Check running processes count
        process_count = len(psutil.pids())
        if process_count > 200:
            score -= 5
            issues.append("High number of running processes")

        # Ensure score doesn't go below 0
        score = max(0, score)

        return jsonify({
            'score': score,
            'issues': issues,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e), 'score': 0}), 500

@app.route('/api/check_password', methods=['POST'])
def check_password():
    """Check password strength"""
    try:
        data = request.get_json()
        password = data.get('password', '')

        if not password:
            return jsonify({'error': 'Password is required'}), 400

        result = check_password_strength(password)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/start_monitor', methods=['POST'])
def start_monitor():
    """Start file integrity monitoring for a folder"""
    global file_monitor

    try:
        data = request.get_json()
        folder_path = data.get('path', '')

        if not folder_path:
            return jsonify({'error': 'Folder path is required'}), 400

        if not os.path.exists(folder_path):
            return jsonify({'error': 'Folder does not exist'}), 400

        # Stop existing monitor if running
        if file_monitor:
            file_monitor.stop()

        # Start new monitor
        file_monitor = FileIntegrityMonitor(folder_path)
        file_monitor.start()

        # Add alert
        add_alert('INFO', f'Started monitoring folder: {folder_path}')

        return jsonify({'message': f'File integrity monitoring started for {folder_path}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
def get_alerts():
    """Get all current security alerts"""
    global alerts
    return jsonify(alerts)

def add_alert(level, message):
    """Add a security alert"""
    global alerts
    alert = {
        'level': level,
        'message': message,
        'timestamp': datetime.now().isoformat()
    }
    alerts.append(alert)

    # Keep only last 100 alerts
    if len(alerts) > 100:
        alerts = alerts[-100:]

if __name__ == '__main__':
    print("Starting Personal Cybersecurity Toolkit...")
    print("Access the dashboard at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)