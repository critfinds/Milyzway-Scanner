import asyncio
import json
import tempfile
from pathlib import Path
from scanner.plugins.base import BasePlugin

class SolidityToolsPlugin(BasePlugin):
    name = "solidity_tools"

    async def run(self, target: str, requester, oast_server: str = None):
        if target.startswith("file://"):
            return await self.scan_file(target)
        elif target.startswith("0x"):
            return await self.scan_address(target, requester)
        else:
            return []

    async def scan_file(self, target: str):
        file_path = Path(target[7:])
        if not file_path.exists() or not file_path.is_file() or file_path.suffix != ".sol":
            return []

        results = []

        # Run Mythril
        mythril_results = await self.run_mythril(file_path)
        if mythril_results:
            results.append({"tool": "mythril", "results": mythril_results})

        # Run Slither
        slither_results = await self.run_slither(file_path)
        if slither_results:
            results.append({"tool": "slither", "results": slither_results})

        return results

    async def scan_address(self, address: str, requester):
        # Etherscan API key (replace with your own)
        api_key = "YOUR_ETHERSCAN_API_KEY"

        # Construct the Etherscan API URL
        url = f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={address}&apikey={api_key}"

        # Fetch the source code from Etherscan
        try:
            response = await requester.get(url)
            response.raise_for_status()
            data = await response.json()
        except Exception as e:
            LOG.error(f"Failed to fetch source code from Etherscan: {e}")
            return []

        if data["status"] != "1":
            LOG.error(f"Etherscan API returned an error: {data[\"message\"]}")
            return []

        source_code = data["result"][0]["SourceCode"]

        # Save the source code to a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
            f.write(source_code)
            file_path = Path(f.name)

        results = []

        # Run Mythril
        mythril_results = await self.run_mythril(file_path)
        if mythril_results:
            results.append({"tool": "mythril", "results": mythril_results})

        # Run Slither
        slither_results = await self.run_slither(file_path)
        if slither_results:
            results.append({"tool": "slither", "results": slither_results})

        # Clean up the temporary file
        file_path.unlink()

        return results

    async def run_mythril(self, file_path: Path):
        process = await asyncio.create_subprocess_shell(
            f"myth analyze {file_path} --execution-timeout 600 --max-depth 22 -o json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            return {"error": stderr.decode() if stderr else "Unknown error"}

        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {"error": "Failed to parse Mythril output"}

    async def run_slither(self, file_path: Path):
        process = await asyncio.create_subprocess_shell(
            f"slither {file_path} --json -",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode not in [0, 255]:
            return {"error": stderr.decode() if stderr else "Unknown error"}

        try:
            results = json.loads(stdout)
            if not results.get("success") or not results.get("results"):
                return {"error": "Slither returned empty results"}
            return results
        except json.JSONDecodeError:
            return {"error": "Failed to parse Slither output"}