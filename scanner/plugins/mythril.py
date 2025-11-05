import subprocess
import json

from scanner.logger import get_logger
from scanner.plugins.base import BasePlugin

LOG = get_logger("vuln-scanner")

class MythrilPlugin(BasePlugin):
    name = "mythril"

    async def run(self, target, requester, oast_server: str = None):
        if target.startswith("file://"):
            filepath = target[7:]
            try:
                result = subprocess.run(
                    ["python", "-m", "mythril.interfaces.cli", "analyze", filepath, "-o", "jsonv2"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                vulnerabilities = json.loads(result.stdout)
                return vulnerabilities
            except FileNotFoundError:
                LOG.error("mythril is not installed or not in your PATH.")
                return "Error: mythril is not installed or not in your PATH."
            except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
                LOG.error(f"Error running mythril or parsing its output: {e}")
                return f"Error running mythril or parsing its output: {e}"
        return None
