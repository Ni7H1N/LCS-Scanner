# scanner/__init__.py
"""
Scanner package exports for LCS-Scanner v5.

Expose parsers, engine, utils and helpers to the top-level import:
    from scanner import rules_engine, ai_explainer, report_generator, utils
"""

# Standard parsers / helpers (keep in sync with files present in the package)
from . import parser_tf, parser_yaml, parser_docker, rules_engine, ai_explainer, report_generator, utils

__all__ = [
    "parser_tf",
    "parser_yaml",
    "parser_docker",
    "rules_engine",
    "ai_explainer",
    "report_generator",
    "utils",
]

# convenience: try to import optional modules (no crash if missing)
_optional_modules = ["intel_enricher", "compliance_mapper", "yara_helpers"]
for _m in _optional_modules:
    try:
        globals()[_m] = __import__(f"scanner.{_m}", fromlist=[_m])
        __all__.append(_m)
    except Exception:
        # optional modules not present — skip silently (caller should handle fallback)
        globals()[_m] = None
