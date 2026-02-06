import sys
import os

# Add project root to path
sys.path.append(os.getcwd())

from gateway.auth_manager import AuthManager

def test_auth_manager():
    print("Initializing AuthManager...")
    try:
        auth = AuthManager()
        result = auth.is_authenticated("192.168.1.100")
        print(f"is_authenticated('192.168.1.100') = {result}")
        if result is True:
            print("SUCCESS: AuthManager allows access.")
            sys.exit(0)
        else:
            print("FAILURE: AuthManager denied access.")
            sys.exit(1)
    except Exception as e:
        print(f"CRASH: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_auth_manager()
