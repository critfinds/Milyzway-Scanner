"""
Base class for plugins
"""

class BasePlugin:
    """
    Base class for all plugins
    """
    def __init__(self):
        self.name = "base"
        self.description = "Base plugin"

    async def run(self, target: str, requester, oast_server: str = None):
        """
        Run the plugin
        """
        raise NotImplementedError
