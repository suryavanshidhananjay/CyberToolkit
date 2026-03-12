from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import psutil
import json
import os
import threading
import datetime
import subprocess
import config

try:
    from modules import file_integrity, process_monitor, network_scanner, password_checker, log_analyzer, ai_advisor
except ImportError as e:
    print(f"Module warning: {e}")

app = Flask(__name__)
CORS(app)
app.secret_key = config.APP_SECRET_KEY


@app.route('/')
def index():
    """Render main application page"""
    try:
        return render_template('index.html')
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route('/api/health_score')
def health_score():
    """Calculate and return system security health score"""
    try:
        # Get suspicious processes and risk level
        suspicious_procs = process_monitor.get_suspicious_processes()
        risk_level = log_analyzer.get_risk_level()
        
        # Calculate score starting at 100
        score = 100
        threats = []
        
        # Deduct for risk level
        if risk_level == "HIGH":
            score -= 15
            threats.append("High security risk detected in logs")
        elif risk_level == "MEDIUM":
            score -= 8
            threats.append("Medium security risk in system logs")
        
        # Deduct for suspicious processes (max 20 points)
        suspicious_count = len(suspicious_procs)
        deduction = min(suspicious_count * 5, 20)
        score -= deduction
        if suspicious_count > 0:
            threats.append(f"{suspicious_count} suspicious process(es) detected")
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        # Determine label
        if score > 70:
            label = "SECURE"
        elif score >= 40:
            label = "AT RISK"
        else:
            label = "CRITICAL"
        
        breakdown = [
            {"category": "Log Analysis", "impact": risk_level},
            {"category": "Process Monitor", "impact": f"{suspicious_count} suspicious"},
            {"category": "Overall Status", "impact": label}
        ]
        
        return jsonify({
            "score": score,
            "label": label,
            "threats": len(threats),
            "breakdown": breakdown
        })
    except Exception as e:
        return jsonify({
            "score": 75,
            "label": "AT RISK",
            "threats": 0,
            "breakdown": []
        })


@app.route('/api/processes')
def get_processes():
    """Get all running processes with suspicious process detection"""
    try:
        processes = process_monitor.get_all_processes()
        suspicious = process_monitor.get_suspicious_processes()
        system_stats = process_monitor.get_system_stats()
        
        return jsonify({
            "processes": processes[:50],  # Limit to top 50
            "suspicious": suspicious,
            "system_stats": system_stats
        })
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route('/api/network')
def get_network():
    """Scan and return network devices"""
    try:
        devices = network_scanner.scan_network()
        
        return jsonify({
            "devices": devices,
            "count": len(devices),
            "timestamp": datetime.datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route('/api/logs')
def get_logs():
    """Analyze system logs for security events"""
    try:
        events = log_analyzer.analyze_logs()
        risk_level = log_analyzer.get_risk_level()
        failed_count = log_analyzer.get_failed_count()
        
        return jsonify({
            "events": events,
            "risk_level": risk_level,
            "failed_count": failed_count,
            "timestamp": datetime.datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route('/api/file_status')
def file_status():
    """Get file integrity monitoring status"""
    try:
        result = file_integrity.check_integrity()
        modified_count = len(result.get('modified', []))
        
        return jsonify({
            "files": result,
            "modified_count": modified_count,
            "status": result.get('status', 'unknown')
        })
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route('/api/start_monitor', methods=['POST'])
def start_monitor():
    """Start file integrity monitoring for specified path"""
    try:
        data = request.get_json()
        path = data.get('path', '.')
        
        result = file_integrity.start_monitoring([path])
        
        return jsonify({
            "success": result.get('success', False),
            "message": result.get('message', 'Monitoring started'),
            "path": path
        })
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route('/api/check_password', methods=['POST'])
def check_password():
    """Check password strength and security"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        analysis = password_checker.check_password(password)
        
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route('/api/alerts')
def get_alerts():
    """Collect security alerts from all modules"""
    try:
        alerts = []
        alert_id = 1
        
        # Process Monitor alerts
        try:
            suspicious = process_monitor.get_suspicious_processes()
            for proc in suspicious[:5]:  # Limit to 5
                alerts.append({
                    "id": alert_id,
                    "type": "suspicious_process",
                    "severity": "HIGH",
                    "message": f"Suspicious process: {proc['name']} (PID: {proc['pid']}) - {proc['reason']}",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "module": "process_monitor"
                })
                alert_id += 1
        except Exception as e:
            print(f"Process monitor alert error: {e}")
        
        # Log Analyzer alerts
        try:
            events = log_analyzer.analyze_logs()
            for event in events[:3]:  # Limit to 3
                alerts.append({
                    "id": alert_id,
                    "type": "log_event",
                    "severity": event.get('severity', 'MEDIUM'),
                    "message": event.get('message', 'Security event detected'),
                    "timestamp": event.get('timestamp', datetime.datetime.now().isoformat()),
                    "module": "log_analyzer"
                })
                alert_id += 1
        except Exception as e:
            print(f"Log analyzer alert error: {e}")
        
        # File Integrity alerts
        try:
            integrity = file_integrity.check_integrity()
            if integrity.get('status') == 'integrity_compromised':
                modified = integrity.get('modified', [])
                if modified:
                    alerts.append({
                        "id": alert_id,
                        "type": "file_modified",
                        "severity": "CRITICAL",
                        "message": f"{len(modified)} file(s) modified: {modified[0].get('path', 'unknown')}",
                        "timestamp": datetime.datetime.now().isoformat(),
                        "module": "file_integrity"
                    })
                    alert_id += 1
        except Exception as e:
            print(f"File integrity alert error: {e}")
        
        # Network Scanner alerts
        try:
            devices = network_scanner.scan_network()
            if len(devices) > 10:
                alerts.append({
                    "id": alert_id,
                    "type": "network_activity",
                    "severity": "MEDIUM",
                    "message": f"High network activity: {len(devices)} devices detected",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "module": "network_scanner"
                })
                alert_id += 1
        except Exception as e:
            print(f"Network scanner alert error: {e}")
        
        critical_count = sum(1 for alert in alerts if alert['severity'] == 'CRITICAL')
        
        return jsonify({
            "alerts": alerts,
            "count": len(alerts),
            "critical_count": critical_count
        })
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route('/api/ask_ai', methods=['POST'])
def ask_ai():
    """Get AI-powered security advice"""
    try:
        data = request.get_json()
        message = data.get('message', '')
        context = data.get('context', {})
        
        response = ai_advisor.get_advice(message, context)
        
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route('/api/summary')
def get_summary():
    """Get comprehensive security summary from all modules"""
    try:
        summary_data = {}
        
        # Collect data from all modules
        try:
            summary_data['processes'] = {
                'total': len(process_monitor.get_all_processes()),
                'suspicious': len(process_monitor.get_suspicious_processes())
            }
        except Exception as e:
            summary_data['processes'] = {'error': str(e)}
        
        try:
            summary_data['network'] = {
                'devices': len(network_scanner.scan_network()),
                'local_ip': network_scanner.get_local_ip()
            }
        except Exception as e:
            summary_data['network'] = {'error': str(e)}
        
        try:
            summary_data['logs'] = {
                'risk_level': log_analyzer.get_risk_level(),
                'failed_count': log_analyzer.get_failed_count()
            }
        except Exception as e:
            summary_data['logs'] = {'error': str(e)}
        
        try:
            integrity = file_integrity.check_integrity()
            summary_data['file_integrity'] = {
                'status': integrity.get('status', 'unknown'),
                'modified': len(integrity.get('modified', []))
            }
        except Exception as e:
            summary_data['file_integrity'] = {'error': str(e)}
        
        # Get AI summary
        try:
            ai_summary = ai_advisor.generate_summary(summary_data)
            summary_data['ai_analysis'] = ai_summary
        except Exception as e:
            summary_data['ai_analysis'] = {'error': str(e)}
        
        summary_data['timestamp'] = datetime.datetime.now().isoformat()
        
        return jsonify(summary_data)
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


if __name__ == "__main__":
    print("CyberGuard AI running at http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
