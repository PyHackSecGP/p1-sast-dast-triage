"""Scanner output parsers."""
from .bandit import BanditParser
from .base import Finding
from .semgrep import SemgrepParser
from .zap import ZapParser

PARSERS = {
    "semgrep": SemgrepParser,
    "bandit": BanditParser,
    "zap": ZapParser,
}

__all__ = ["Finding", "SemgrepParser", "BanditParser", "ZapParser", "PARSERS"]
