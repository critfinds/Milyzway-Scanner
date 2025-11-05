import ast
from scanner.plugins.base import BasePlugin

class Plugin(BasePlugin):
    name = "command_injection"

    async def run(self, target: str, requester, oast_server: str = None):
        if not target.startswith("http"):
            return []

        try:
            response = await requester.get(target)
            await response.raise_for_status()
            text = await response.text()
        except Exception:
            return []

        results = []

        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "system" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    results.append({
                        "plugin": self.name,
                        "tool": "command_injection",
                        "type": "os.system",
                        "target": target,
                        "message": f"Use of os.system() found in {target}",
                    })
        except Exception:
            pass

        return results
