
from .base import BasePlugin
import subprocess
import json
from typing import Dict, Any

class Plugin(BasePlugin):
    name = "subdomain_takeover"

    async def run(self, target: str, requester, oast_server: str = None) -> Dict[str, Any] | None:
        try:
            # We need to extract the domain from the target URL
            domain = target.split("//")[-1].split("/")[0]

            # Run subzy
            result = subprocess.run(
                ["subzy", "run", "--targets", domain, "--output", "json"],
                capture_output=True,
                text=True,
                check=True,
            )

            # Parse the JSON output
            findings = json.loads(result.stdout)

            if findings:
                return {"subdomain_takeover_findings": findings}
            return None

        except FileNotFoundError:
            return {"error": "Subdomain takeover scan failed: 'subzy' not found. Please make sure it is installed and in your PATH."}
        except subprocess.CalledProcessError as e:
            return {"error": f"Subdomain takeover scan failed: {e.stdout}"}
        except json.JSONDecodeError:
            return {"error": "Subdomain takeover scan failed: Invalid JSON output from subzy."}
        except Exception as e:
            return {"error": f"An unexpected error occurred during subdomain takeover scan: {e}"}
