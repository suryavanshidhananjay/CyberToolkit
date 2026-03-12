# 🛡️ CyberGuard AI

A comprehensive cybersecurity monitoring and threat detection platform powered by Google Gemini AI, designed to provide real-time security insights and automated threat analysis for macOS systems.

---

## ✨ Features

- **System Process Audit** - Monitor running processes with intelligent suspicious activity detection
- **File Integrity Monitor** - Track file changes and detect unauthorized modifications in real-time
- **Network Device Scanner** - Discover and analyze all devices connected to your network
- **Password Strength Analyzer** - Evaluate password security with detailed strength metrics
- **Security Log Analyzer** - Parse system logs to identify authentication failures and security events
- **Gemini AI Threat Advisor** - Get AI-powered security recommendations and threat remediation guidance

---

## 🛠️ Tech Stack

- **Backend**: Python, Flask, Flask-CORS
- **System Monitoring**: psutil
- **AI Integration**: Google Gemini AI API
- **Frontend**: HTML5, CSS3, JavaScript
- **Visualization**: Chart.js
- **Icons**: Font Awesome
- **Data Processing**: JSON, subprocess, threading

---

## 📋 Prerequisites

Before running CyberGuard AI, ensure you have the following installed:

- **Python 3.8+**
- **pip3** (Python package manager)
- **Google Gemini API Key** ([Get one here](https://makersuite.google.com/app/apikey))
- **macOS** (for full system monitoring features)

---

## 🚀 Installation

Follow these steps to set up CyberGuard AI on your local machine:

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/CyberGuardAI.git
   cd CyberGuardAI
   ```

2. **Create a virtual environment**
   ```bash
   python3 -m venv venv
   ```

3. **Activate the virtual environment**
   ```bash
   source venv/bin/activate
   ```

4. **Install required dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Configure your Gemini API key**
   
   Open `config.py` and add your API key:
   ```python
   GEMINI_API_KEY = "your_api_key_here"
   APP_SECRET_KEY = "your_secret_key_here"
   ```

6. **Run the application**
   ```bash
   python3 app.py
   ```

7. **Access the dashboard**
   
   Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

---

## 📡 API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/` | Render main dashboard interface |
| GET | `/api/health_score` | Calculate overall system security health score |
| GET | `/api/processes` | Retrieve all running processes and suspicious activity |
| GET | `/api/network` | Scan and list all network-connected devices |
| GET | `/api/logs` | Analyze system logs for security events |
| GET | `/api/file_status` | Check file integrity monitoring status |
| POST | `/api/start_monitor` | Start file integrity monitoring for specified path |
| POST | `/api/check_password` | Analyze password strength and security |
| GET | `/api/alerts` | Retrieve aggregated security alerts from all modules |
| POST | `/api/ask_ai` | Get AI-powered security advice and recommendations |
| GET | `/api/summary` | Generate comprehensive security summary report |

---

## 📁 Project Structure

```
CyberGuardAI/
├── app.py                      # Main Flask application
├── config.py                   # Configuration and API keys
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
│
├── modules/                    # Security monitoring modules
│   ├── __init__.py
│   ├── ai_advisor.py          # Gemini AI integration
│   ├── file_integrity.py      # File monitoring system
│   ├── log_analyzer.py        # System log parser
│   ├── network_scanner.py     # Network device scanner
│   ├── password_checker.py    # Password strength analyzer
│   └── process_monitor.py     # Process auditing tool
│
├── templates/                  # HTML templates
│   └── index.html             # Main dashboard
│
├── static/                     # Static assets
│   ├── css/
│   │   └── style.css          # Custom styles
│   └── js/
│       └── main.js            # Frontend JavaScript
│
└── backend/                    # Legacy backend files
    ├── config.py
    ├── log_analyzer.py
    ├── network_scanner.py
    ├── process_monitor.py
    └── requirements.txt
```

---

## 👥 Team

| Name | Role | GitHub |
|------|------|--------|
| Member 1 | Full Stack Developer | [@username1](https://github.com/username1) |
| Member 2 | Security Engineer | [@username2](https://github.com/username2) |
| Member 3 | AI Integration Specialist | [@username3](https://github.com/username3) |
| Member 4 | Frontend Developer | [@username4](https://github.com/username4) |

---

## 📄 License

MIT License

Copyright (c) 2026 CyberGuard AI Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Support

For support, email support@cyberguardai.com or open an issue in the repository.

---

**Made with ❤️ by the CyberGuard AI Team**
