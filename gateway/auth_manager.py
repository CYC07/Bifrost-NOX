import logging

logger = logging.getLogger("auth_manager")

class AuthManager:
    def __init__(self):
        pass
        
    def is_authenticated(self, ip_address: str) -> bool:
        """
        Open Network Mode: Always returns True.
        Authentication is no longer required.
        """
        return True
