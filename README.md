# Phishing URL Checker (Lite)

A simple web application to check if a URL is potentially a phishing site. This tool analyzes various factors including URL structure, SSL certificates, domain age, and content to determine the risk level.

⚠️ **This is a basic phishing URL checker and should not be relied upon as the sole security measure.**

## Features

-  URL structure analysis (suspicious patterns, TLDs, keywords)
-  SSL certificate verification
-  Domain age checking (WHOIS lookup)
-  Content analysis for phishing indicators
-  Risk scoring system (Safe, Low Risk, Medium Risk, High Risk)
-  Modern, responsive UI
-  Real-time URL analysis

## Quick Start

**Windows:**
```bash
setup.bat
```

**Linux/Mac:**
```bash
chmod +x setup.sh
./setup.sh
```

This will automatically create a virtual environment and install all dependencies.

## Installation

### Manual Installation

1. **Clone or download this repository**

2. **Create a virtual environment:**
   
   **Windows:**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```
   
   **Linux/Mac:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Easy Way (Using Run Script)

**Windows:**
```bash
run.bat
```

**Linux/Mac:**
```bash
chmod +x run.sh
./run.sh
```

### Manual Way

1. **Activate the virtual environment:**
   
   **Windows:**
   ```bash
   venv\Scripts\activate
   ```
   
   **Linux/Mac:**
   ```bash
   source venv/bin/activate
   ```

2. **Run the Flask application:**
   ```bash
   python app.py
   ```

3. **Open your web browser and navigate to:**
   ```
   http://localhost:5000
   ```

4. **Enter a URL to check** in the input field and click "Check URL"

5. **Review the results:**
   - Risk level (Safe, Low Risk, Medium Risk, High Risk)
   - Risk score (0-100+)
   - List of issues found
   - Detailed analysis

## Risk Levels

- **SAFE (0-19)**: URL appears to be legitimate
- **LOW RISK (20-39)**: Some minor concerns, proceed with caution
- **MEDIUM RISK (40-69)**: Multiple warning signs, be cautious
- **HIGH RISK (70+)**: Strong indicators of phishing, avoid this URL

## How It Works

The checker analyzes URLs based on:

1. **URL Structure**: Checks for IP addresses, suspicious TLDs, unusual patterns, homoglyph attacks
2. **SSL Certificate**: Verifies certificate validity and expiration
3. **Domain Age**: Checks when the domain was registered (newer domains are more suspicious)
4. **Content Analysis**: Scans page content for common phishing indicators
5. **Reachability**: Verifies if the URL is accessible and checks for redirects

## Requirements

- Python 3.7 or higher
- Flask
- requests
- whois


