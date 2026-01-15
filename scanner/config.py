"""Configuration loader for the scanner.

Reads YAML (if available) or JSON and returns a dict merged with sane
defaults. The function is intentionally defensive: missing config file
falls back to defaults and invalid types are ignored.
"""
from pathlib import Path
import json
import os
from typing import Dict, Any

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


DEFAULTS: Dict[str, Any] = {
    "targets": [],
    "enabled_plugins": [
        "cors",
        "csrf",
        "file_upload",
        "graphql",
        "idor",
        "insecure_deserialization",
        "jwt_auth",
        "open_redirect",
        "path_traversal",
        "rce",
        "sqli",
        "ssrf",
        "ssti",
        "waf_bypass",
        "xpath",
        "xss",
        "xxe",
    ],
    "concurrency": 5,
    "rate_limit": 5,
    "output_path": "./scan_results.json",
    "safe_mode": True,
    "timeout": 10,
    "http": {"timeout": 10, "proxies": None},
}


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    cfg: Dict[str, Any] = DEFAULTS.copy()

    p = Path(config_path)
    if not p.exists():
        # allow env overrides even when file missing
        _apply_env_overrides(cfg)
        _ensure_output_path(cfg)
        return cfg

    try:
        text = p.read_text(encoding="utf-8")
        data: Dict[str, Any] = {}
        if yaml:
            try:
                data = yaml.safe_load(text) or {}
            except Exception:
                data = {}
        else:
            try:
                data = json.loads(text)
            except Exception:
                data = {}

        if isinstance(data, dict):
            cfg.update(data)
    except Exception:
        # if anything goes wrong reading/parsing, fall back to defaults
        pass

    _apply_env_overrides(cfg)
    _ensure_output_path(cfg)
    return cfg


def _apply_env_overrides(cfg: Dict[str, Any]) -> None:
    if "VULN_CONCURRENCY" in os.environ:
        try:
            cfg["concurrency"] = int(os.environ["VULN_CONCURRENCY"])
        except Exception:
            pass
    if "VULNSCANNER_RATE_LIMIT" in os.environ:
        try:
            cfg["rate_limit"] = int(os.environ["VULNSCANNER_RATE_LIMIT"])
        except Exception:
            pass
    if "VULNSCANNER_SAFE_MODE" in os.environ:
        val = os.environ["VULNSCANNER_SAFE_MODE"].lower()
        cfg["safe_mode"] = val in ("1", "true", "yes", "on")


def _ensure_output_path(cfg: Dict[str, Any]) -> None:
    out = cfg.get("output_path") or DEFAULTS["output_path"]
    p = Path(out)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        cfg["output_path"] = str(p)
    except Exception:
        cfg["output_path"] = DEFAULTS["output_path"]

