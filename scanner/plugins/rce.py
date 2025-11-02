import ast
from scanner.plugins.base import BasePlugin

class RcePlugin(BasePlugin):
    name = "rce"

    async def run(self, target: str, requester, oast_server: str = None):
        if not target.startswith("http"):
            return []

        try:
            response = await requester.get(target)
            response.raise_for_status()
            text = await response.text()
        except Exception:
            return []

        results = []

        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":
                    results.append({
                        "plugin": self.name,
                        "tool": "rce",
                        "type": "eval",
                        "target": target,
                        "message": f"Use of eval() found in {target}",
                    })
        except Exception:
            pass

        return results
