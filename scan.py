import os
import sys
import winreg
import socket
import subprocess
import platform
import psutil
import logging
import time
import wmi
import hashlib
from datetime import datetime
import threading

class WindowsVulnScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.log_file = "win_vuln_scan_log.txt"
        logging.basicConfig(filename=self.log_file, level=logging.INFO,
                           format='%(asctime)s - %(levelname)s - %(message)s')
        self.wmi_client = wmi.WMI()

    def check_os_version(self):
        """Check if OS is outdated or unpatched"""
        os_info = platform.win32_ver()
        version = os_info[1]
        print(f"\nOS Version: {version}")
        # Example: Windows 10 versions below 22H2 might be considered outdated
        if "10" in version and int(version.split('.')[2]) < 19044:
            self.vulnerabilities.append("Outdated Windows version detected")
            print("Warning: Your Windows version might be outdated")
        logging.info("OS version check completed")

    def check_updates(self):
        """Check for missing Windows updates"""
        print("\nChecking for Windows updates...")
        try:
            result = subprocess.check_output("wmic qfe list", shell=True, text=True)
            if not result.strip():
                self.vulnerabilities.append("No updates installed or update check failed")
                print("Warning: No updates detected")
            else:
                print("Updates found. Check log for details.")
            logging.info("Windows updates check completed")
        except Exception as e:
            print(f"Error: {e}")
            self.vulnerabilities.append("Failed to check updates")

    def check_firewall(self):
        """Verify Windows Firewall status"""
        print("\nChecking Firewall status...")
        try:
            result = subprocess.check_output("netsh advfirewall show allprofiles state", shell=True, text=True)
            if "OFF" in result.upper():
                self.vulnerabilities.append("Windows Firewall is disabled")
                print("Warning: Firewall is OFF")
            else:
                print("Firewall is enabled")
            logging.info("Firewall check completed")
        except Exception as e:
            print(f"Error: {e}")

    def check_defender(self):
        """Check Windows Defender status"""
        print("\nChecking Windows Defender status...")
        try:
            defender = self.wmi_client.Win32_Service(Name="WinDefend")[0]
            if defender.State != "Running":
                self.vulnerabilities.append("Windows Defender is not running")
                print("Warning: Defender is not running")
            else:
                print("Defender is active")
            logging.info("Defender check completed")
        except Exception as e:
            print(f"Error: {e}")

    def check_open_ports(self):
        """Scan for open ports"""
        print("\nScanning open ports...")
        open_ports = []
        for conn in psutil.net_connections():
            if conn.status == "LISTEN":
                open_ports.append(conn.laddr.port)
        if open_ports:
            self.vulnerabilities.append(f"Open ports detected: {open_ports}")
            print(f"Open ports: {open_ports}")
        else:
            print("No unexpected open ports found")
        logging.info("Open ports scan completed")

    def check_admin_accounts(self):
        """Check for excessive admin accounts"""
        print("\nChecking admin accounts...")
        try:
            result = subprocess.check_output("net localgroup Administrators", shell=True, text=True)
            admins = [line.strip() for line in result.splitlines() if line.strip() and "----" not in line and "command completed" not in line]
            if len(admins) > 2:  # More than built-in admin + current user
                self.vulnerabilities.append(f"Multiple admin accounts detected: {admins}")
                print(f"Warning: Found {len(admins)} admin accounts: {admins}")
            else:
                print("Admin account count looks normal")
            logging.info("Admin accounts check completed")
        except Exception as e:
            print(f"Error: {e}")

    def check_registry_security(self):
        """Check registry for security settings"""
        print("\nChecking registry settings...")
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
                value, _ = winreg.QueryValueEx(key, "everyoneincludesanonymous")
                if value != 0:
                    self.vulnerabilities.append("Anonymous access to SAM allowed")
                    print("Warning: Anonymous SAM access enabled")
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
                value, _ = winreg.QueryValueEx(key, "LocalAccountTokenFilterPolicy")
                if value == 1:
                    self.vulnerabilities.append("UAC remote restrictions disabled")
                    print("Warning: UAC remote restrictions disabled")
            logging.info("Registry security check completed")
        except Exception as e:
            print(f"Error checking registry: {e}")

    def check_file_permissions(self):
        """Check critical file permissions"""
        print("\nChecking file permissions...")
        critical_files = [r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\drivers\etc\hosts"]
        for file in critical_files:
            try:
                result = subprocess.check_output(f"icacls \"{file}\"", shell=True, text=True)
                if "Everyone:(F)" in result or "Users:(F)" in result:
                    self.vulnerabilities.append(f"Insecure permissions on {file}")
                    print(f"Warning: Insecure permissions on {file}")
            except Exception as e:
                print(f"Error checking {file}: {e}")
        logging.info("File permissions check completed")

    def check_installed_software(self):
        """Check for outdated or vulnerable software"""
        print("\nChecking installed software...")
        try:
            software = self.wmi_client.Win32_Product()
            for app in software[:10]:  # Limit for demo
                print(f"Found: {app.Name} - {app.Version}")
                # Simple check: outdated software (customize as needed)
                if "Adobe" in app.Name and app.Version < "23.0":
                    self.vulnerabilities.append(f"Outdated {app.Name} ({app.Version})")
                    print(f"Warning: Outdated {app.Name}")
            logging.info("Software check completed")
        except Exception as e:
            print(f"Error: {e}")

    def check_password_policy(self):
        """Check local password policy"""
        print("\nChecking password policy...")
        try:
            result = subprocess.check_output("net accounts", shell=True, text=True)
            if "Minimum password length: 0" in result:
                self.vulnerabilities.append("No minimum password length set")
                print("Warning: No minimum password length")
            if "Lockout threshold: Never" in result:
                self.vulnerabilities.append("No account lockout policy")
                print("Warning: No account lockout policy")
            logging.info("Password policy check completed")
        except Exception as e:
            print(f"Error: {e}")

    def check_shares(self):
        """Check for open network shares"""
        print("\nChecking network shares...")
        try:
            result = subprocess.check_output("net share", shell=True, text=True)
            shares = [line.split()[0] for line in result.splitlines() if line.strip() and "Share name" not in line]
            if len(shares) > 2:  # Beyond default ADMIN$ and C$
                self.vulnerabilities.append(f"Multiple shares detected: {shares}")
                print(f"Warning: Found shares: {shares}")
            else:
                print("Shares look normal")
            logging.info("Shares check completed")
        except Exception as e:
            print(f"Error: {e}")

    def generate_report(self):
        """Generate a vulnerability report"""
        report = f"Windows Vulnerability Scan Report - {datetime.now()}\n"
        report += "=" * 50 + "\n"
        report += f"System: {platform.system()} {platform.release()}\n"
        report += "\nVulnerabilities Found:\n"
        if not self.vulnerabilities:
            report += "No critical vulnerabilities detected\n"
        for vuln in self.vulnerabilities:
            report += f"- {vuln}\n"
        with open("win_vuln_report.txt", "w") as f:
            f.write(report)
        print("\nReport generated: win_vuln_report.txt")
        logging.info("Report generated")

    def run_full_scan(self):
        """Run all checks"""
        print("Starting full Windows vulnerability scan...")
        self.check_os_version()
        self.check_updates()
        self.check_firewall()
        self.check_defender()
        self.check_open_ports()
        self.check_admin_accounts()
        self.check_registry_security()
        self.check_file_permissions()
        self.check_installed_software()
        self.check_password_policy()
        self.check_shares()
        self.generate_report()

    def menu(self):
        """Display menu and handle user input"""
        while True:
            print("\n=== Windows Vulnerability Scanner ===")
            print("1. Check OS Version")
            print("2. Check Windows Updates")
            print("3. Check Firewall Status")
            print("4. Check Windows Defender")
            print("5. Check Open Ports")
            print("6. Check Admin Accounts")
            print("7. Check Registry Security")
            print("8. Check File Permissions")
            print("9. Check Installed Software")
            print("10. Check Password Policy")
            print("11. Check Network Shares")
            print("12. Run Full Scan")
            print("13. Exit")

            choice = input("Enter choice (1-13): ")

            if choice == "1":
                self.check_os_version()
            elif choice == "2":
                self.check_updates()
            elif choice == "3":
                self.check_firewall()
            elif choice == "4":
                self.check_defender()
            elif choice == "5":
                self.check_open_ports()
            elif choice == "6":
                self.check_admin_accounts()
            elif choice == "7":
                self.check_registry_security()
            elif choice == "8":
                self.check_file_permissions()
            elif choice == "9":
                self.check_installed_software()
            elif choice == "10":
                self.check_password_policy()
            elif choice == "11":
                self.check_shares()
            elif choice == "12":
                self.run_full_scan()
            elif choice == "13":
                print("Exiting...")
                sys.exit()
            else:
                print("Invalid choice!")

if __name__ == "__main__":
    if platform.system() != "Windows":
        print("This tool is designed for Windows only!")
        sys.exit()
    scanner = WindowsVulnScanner()
    print("Welcome to Windows Vulnerability Scanner")
    scanner.menu()