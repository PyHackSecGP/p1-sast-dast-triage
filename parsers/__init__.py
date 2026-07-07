"""Scanner output parsers."""

from .bandit import BanditParser
from .base import Finding
from .nuclei import NucleiParser
from .semgrep import SemgrepParser
from .trivy import TrivyParser
from .zap import ZapParser

PARSERS = {
    "semgrep": SemgrepParser,
    "bandit": BanditParser,
    "zap": ZapParser,
    "nuclei": NucleiParser,
    "trivy": TrivyParser,
}

__all__ = [
    "PARSERS",
    "BanditParser",
    "Finding",
    "NucleiParser",
    "SemgrepParser",
    "TrivyParser",
    "ZapParser",
]
