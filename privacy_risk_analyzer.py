import sys
import json
from androguard.core.apk import APK
from tabulate import tabulate

# List of permissions considered high risk
HIGH_RISK_PERMISSIONS = [
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_CALL_LOG',
    'android.permission.CAMERA',
    'android.permission.RECORD_AUDIO',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.READ_PHONE_STATE',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.INTERNET',
]

# List of sensitive API keywords to scan for in code
SENSITIVE_API_KEYWORDS = [
    'getLastKnownLocation',
    'requestLocationUpdates',
    'getDeviceId',
    'getLine1Number',
    'getSimSerialNumber',
    'getSubscriberId',
    'getAccounts',
    'getContacts',
    'getCallLog',
    'getSms',
    'Camera',
    'MediaRecorder',
    'AudioRecord',
    'getInstalledPackages',
    'getInstalledApplications',
    'getSerial',
    'getMacAddress',
    'getSSID',
]


def scan_sensitive_apis(apk):
    """
    Scan the APK's DEX code for sensitive API usage.
    Returns a set of found sensitive API keywords.
    """
    found = set()
    try:
        for dex in apk.get_all_dex():
            code = dex.decode('utf-8', errors='ignore')
            for keyword in SENSITIVE_API_KEYWORDS:
                if keyword in code:
                    found.add(keyword)
    except Exception:
        pass  # If DEX extraction fails, skip
    return list(found)


def analyze_apk(apk_path):
    apk = APK(apk_path)
    permissions = apk.get_permissions()
    high_risk = [p for p in permissions if p in HIGH_RISK_PERMISSIONS]
    normal = [p for p in permissions if p not in HIGH_RISK_PERMISSIONS]
    sensitive_apis = scan_sensitive_apis(apk)
    risk_score = len(high_risk) * 2 + len(normal) + len(sensitive_apis) * 2
    risk_level = 'High' if risk_score > 12 else 'Medium' if risk_score > 6 else 'Low'
    report = {
        'app_name': apk.get_app_name(),
        'package': apk.get_package(),
        'permissions': permissions,
        'high_risk_permissions': high_risk,
        'sensitive_apis': sensitive_apis,
        'risk_score': risk_score,
        'risk_level': risk_level,
    }
    return report


def print_report(report):
    print(f"App Name: {report['app_name']}")
    print(f"Package: {report['package']}")
    print(f"Risk Score: {report['risk_score']} ({report['risk_level']})\n")
    print("High Risk Permissions:")
    if report['high_risk_permissions']:
        print(tabulate([[p] for p in report['high_risk_permissions']], headers=["Permission"]))
    else:
        print("None")
    print("\nSensitive API Usage:")
    if report['sensitive_apis']:
        print(tabulate([[a] for a in report['sensitive_apis']], headers=["API Keyword"]))
    else:
        print("None")
    print("\nAll Permissions:")
    print(tabulate([[p] for p in report['permissions']], headers=["Permission"]))


def main():
    if len(sys.argv) < 2:
        print("Usage: python privacy_risk_analyzer.py <path_to_apk>")
        sys.exit(1)
    apk_path = sys.argv[1]
    report = analyze_apk(apk_path)
    print_report(report)
    # Also save as JSON
    with open('privacy_risk_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print("\nReport saved to privacy_risk_report.json")


if __name__ == "__main__":
    main() 