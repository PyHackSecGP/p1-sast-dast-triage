"""Report output formatters."""
from .json_report import write_json
from .markdown_report import write_markdown

__all__ = ["write_json", "write_markdown"]
