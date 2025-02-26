# Windows Vulnerability Scanner

## Dependencies
Install these Python packages:

    pip install psutil wmi pywin32
    
## Features of the Scanner
1.  OS Version Check: Identifies outdated Windows versions.
2.  Updates Check: Verifies if updates are installed.
3.  Firewall Check: Ensures Windows Firewall is active.
4.  Defender Check: Confirms Windows Defender is running.
5.  Open Ports Check: Scans for unexpected open ports.
6.  Admin Accounts Check: Detects excessive admin users.
7.  Registry Security Check: Analyzes critical registry settings.
8.  File Permissions Check: Examines permissions on sensitive files.
9.  Installed Software Check: Looks for outdated software.
10.  Password Policy Check: Verifies password and lockout policies.
11.  Network Shares Check: Identifies exposed shares.
12.  Full Scan: Runs all checks and generates a report.
13.  Report Generation: Outputs findings to a file.

## Robustness Features
1.  Error Handling: Prevents crashes with try-except blocks.
2.  Logging: Records all actions in win_vuln_scan_log.txt.
3.  WMI Integration: Uses Windows Management Instrumentation for deeper system insights.
4.  Modular Design: Easy to add new checks.
5.  Threading Potential: Can be extended for faster scanning.

## How to Use
Save the code as scan.py.

Install dependencies using pip.

Run with python 

    scan.py 
    
  (preferably as Administrator for full access).
  
Choose individual checks or run a full scan from the menu.

##  Notes

Admin Privileges: Some checks (e.g., registry, shares) require running as Administrator.

Customization: Adjust thresholds (e.g., outdated software versions) based on your needs.

Limitations: This is a basic scanner; for advanced vuln scanning, combine with tools like Nessus or OpenVAS.

This tool gives you a Blue Team-focused view of your Windows system’s security posture, highlighting areas to fix. 
