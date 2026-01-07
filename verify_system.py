import requests
import time
import os

PROXIES = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080",
}
# Bypass proxy for local services calls if needed, but we want to TEST the proxy.
# We need a target to send data TO. 
# We can just send to "http://example.com" (outbound) or specific test endpoints.

TARGET_URL = "http://httpbin.org/post" 

def test_safe_text():
    print("\n--- Testing Safe Text ---")
    try:
        resp = requests.post(
            TARGET_URL, 
            data="Hello, this is a safe message.", 
            headers={"Content-Type": "text/plain"},
            proxies=PROXIES,
            verify=False,
            timeout=5
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code == 200:
            print("PASS: Safe text allowed.")
        else:
            print("FAIL: Safe text blocked.")
    except Exception as e:
        print(f"FAIL: Request error: {e}")

def test_threat_text():
    print("\n--- Testing Threat Text ---")
    try:
        resp = requests.post(
            TARGET_URL, 
            data="Run eval(bad_code) and kill the process! API_KEY=12345", 
            headers={"Content-Type": "text/plain"},
            proxies=PROXIES,
            verify=False,
            timeout=5
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code == 403:
            print("PASS: Threat text blocked.")
        else:
            print("FAIL: Threat text allowed.")
    except Exception as e:
        print(f"FAIL: Request error: {e}")

def main():
    print("Waiting for services to settle...")
    time.sleep(5)
    
    test_safe_text()
    test_threat_text()
    
    # We could test images too if we had sample files
    
if __name__ == "__main__":
    main()
