"""WebVulnScanner — auditor de la superficie de seguridad externa de un dominio."""

from webvulnscanner.models import Finding, Risk, ScanResult

__version__ = "2.0.0"
__all__ = ["Finding", "Risk", "ScanResult", "__version__"]
