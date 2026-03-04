"""Base normalizer interface. All source normalizers must implement this."""

from abc import ABC, abstractmethod
from src.ocsf_schema import OCSFEvent


class BaseNormalizer(ABC):
    """
    Abstract base for all log source normalizers.
    To onboard a new source: subclass BaseNormalizer, implement normalize(),
    and register in NORMALIZER_REGISTRY in pipeline.py.
    """

    @abstractmethod
    def normalize(self, raw: dict) -> OCSFEvent:
        """Transform a raw log dict into a normalized OCSFEvent."""
        pass

    def _safe_int(self, value, default=0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _safe_str(self, value, default="") -> str:
        if value is None:
            return default
        return str(value).strip()
