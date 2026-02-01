import requests

# SQL error indicators
SQL_ERRORS = [
    "sql syntax",
    "mysql",
    "warning",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-"
]

def load_payloads():
    with open("payloads.txt", "r") as file:
        return [line.strip() for line in file.readlines()]

def scan(url):
    payloads = load_payloads()
    vulnerable = False

    print("Starting SQL Injection Scan...\n")

    for payload in payloads:
        test_url = url + payload
        print(f"Testing: {test_url}")

        try:
            response = requests.get(test_url, timeout=5)
            content = response.text.lower()

            for error in SQL_ERRORS:
                if error in content:
                    print(f"[!] Vulnerable payload detected: {payload}")
                    vulnerable = True

                    with open("report.txt", "a") as report:
                        report.write(f"VULNERABLE with payload: {payload}\n")

                    break

        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")

    if not vulnerable:
        print("\nNo SQL Injection vulnerability detected.")
    else:
        print("\nScan completed. Vulnerabilities found.")

if __name__ == "__main__":
    target_url = input("Enter test URL (with parameter): ")
    scan(target_url)
