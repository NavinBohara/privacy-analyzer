# Privacy Risk Analyzer for Social Media Android Apps

This tool evaluates Android APKs by analyzing permissions and sensitive API usage to identify privacy risks.

## Features
- Extracts app permissions from APKs
- Flags high-risk permissions
- Scans for sensitive API usage (contacts, location, camera, etc.)
- Outputs a CLI and JSON risk report

## Setup
1. Install Python 3.8+
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage
```sh
python privacy_risk_analyzer.py path/to/app.apk
```
- View the CLI report
- See `privacy_risk_report.json` for a JSON version

## How It Works
- Extracts permissions using androguard
- Flags high-risk permissions
- Scans APK code for sensitive API calls
- Assigns a risk score and level

## Extending
- Add more sensitive APIs to scan for
- Integrate dynamic analysis or a web dashboard

---

*For research and educational use only.* 