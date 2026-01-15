"""
Base class for plugins
"""

class BasePlugin:
    """
    Base class for all plugins
    """
    # Default class attributes (can be overridden by child classes)
    name = "base"
    description = "Base plugin"
    severity = "info"
    confidence = "tentative"

    def __init__(self):
        # Only set instance attributes if not already defined as class attributes
        # This allows child classes to set these as class attributes
        if not hasattr(self.__class__, 'name') or self.__class__.name == BasePlugin.name:
            self.name = "base"
        if not hasattr(self.__class__, 'description') or self.__class__.description == BasePlugin.description:
            self.description = "Base plugin"

    async def run(self, target: str, requester, oast_server: str = None):
        """
        Run the plugin
        """
        raise NotImplementedError

    @staticmethod
    def is_valid_target(response: dict) -> bool:
        """
        Check if the target is valid (not 404, 403, 5xx, etc.)

        Args:
            response: Response dictionary from requester

        Returns:
            bool: True if target is valid, False otherwise
        """
        if not response or not isinstance(response, dict):
            return False

        status = response.get("status", 0)

        # Consider only 2xx status codes as valid targets
        # Exclude 404 (Not Found), 403 (Forbidden), 5xx (Server Errors)
        if status < 200 or status >= 400:
            return False

        return True

    @staticmethod
    def is_error_page(response: dict) -> bool:
        """
        Check if response is an error page (404, 403, 5xx, etc.)

        Args:
            response: Response dictionary from requester

        Returns:
            bool: True if error page, False otherwise
        """
        if not response or not isinstance(response, dict):
            return True

        status = response.get("status", 0)

        # Common error status codes
        if status in [400, 401, 403, 404, 405, 500, 501, 502, 503, 504]:
            return True

        # Check for common error page patterns in content
        text = response.get("text", "").lower()
        error_patterns = [
            "404 not found",
            "page not found",
            "not found",
            "404 error",
            "403 forbidden",
            "access denied",
            "internal server error",
            "500 error",
        ]

        # If status is error-like and text contains error patterns
        if status >= 400 and any(pattern in text for pattern in error_patterns):
            return True

        return False
