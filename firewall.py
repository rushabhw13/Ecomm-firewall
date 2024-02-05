import subprocess
import platform
import ctypes
import sys

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

iptables_command = 'iptables' if platform.system() != 'Windows' else 'netsh'

ALLOW_SSH = {
    "port": 22,
    "protocol": "tcp"
}

ALLOW_HTTP = {
    "port": 80,
    "protocol": "tcp"
}

DROP_EVERYTHING_ELSE = {
    "default": "DROP"
}

TEST_CASES = [
    {"input": {"protocol": "tcp", "port": 22}, "expect": "ALLOW"},
    {"input": {"protocol": "tcp", "port": 80}, "expect": "ALLOW"},
    {"input": {"protocol": "tcp", "port": 443}, "expect": "DROP"},
    {"input": {"protocol": "tcp", "port": 8080}, "expect": "DROP"}
]
def add_rules(rule):
    # Firewall rules
    if platform.system() == 'Windows':
        if "default" in rule:
            # Special case for DROP_EVERYTHING_ELSE
            action = rule["default"]
            subprocess.run(['powershell', '-Command', f'New-NetFirewallRule -DisplayName FirewallRule -Direction Inbound -Action {action} -Profile Any'], capture_output=True, text=True)
        else:
            # Normal case for ALLOW rules
            protocol = rule.get("protocol", "tcp")
            port = rule.get("port", None)
            if port is not None:
                subprocess.run(['powershell', '-Command', f'New-NetFirewallRule -DisplayName FirewallRule -Direction Inbound -Action Allow -Protocol {protocol} -LocalPort {port} -Profile Any'], capture_output=True, text=True)
                print(f"Rule added successfully: {rule}")
            else:
                print(f"Error: 'port' key not found in the rule: {rule}")
    else:
        print("Unsupported platform")




def setup_firewall():
    # Setup code
    add_rules(ALLOW_SSH)
    add_rules(ALLOW_HTTP)
    add_rules(DROP_EVERYTHING_ELSE)

def test_firewall(test):
    # Test code
    protocol = test["input"].get("protocol", "tcp")
    port = test["input"].get("port")
    expected_action = test["expect"]

    if platform.system() == 'Windows':
        if port is not None:
            # Print the rules after they are added
            subprocess.run(['powershell', '-Command', 'Get-NetFirewallRule -DisplayName FirewallRule | Format-Table -AutoSize'], capture_output=True, text=True)

            cmd = ['powershell', '-Command', f'Get-NetFirewallRule -DisplayName FirewallRule | Where-Object {{ $_.Direction -eq "Inbound" -and $_.Protocol -eq "{protocol}" -and $_.LocalPort -eq "{port}" }}']
            result = subprocess.run(cmd, capture_output=True, text=True)

            # Check if the rule is present in the output
            rule_present = len(result.stdout.strip()) > 0

            if rule_present:
                print(f"Test passed for rule: {test}")
            else:
                print(f"Test failed for rule: {test}")
        else:
            print("Error: 'port' key not found in the test case.")
    else:
        print("Unsupported platform")



def main():
    setup_firewall()

    for test in TEST_CASES:
        test_firewall(test)
  
    print("Firewall active!")
    sys.stdout.flush()

if __name__ == "__main__":
    main()
    input("Press Enter to exit...")
