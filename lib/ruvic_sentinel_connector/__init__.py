"""Conector Ruvic: cliente HTTP del plano de control Sentinel."""

from .client import SentinelClient
from .config import ENV_PREFIX, SentinelConfig
from .exceptions import (
    SentinelAuthError,
    SentinelConnectorError,
    SentinelDataError,
    SentinelNetworkError,
)
from .logging_utils import setup_logging

__all__ = [
    "ENV_PREFIX",
    "SentinelAuthError",
    "SentinelClient",
    "SentinelConfig",
    "SentinelConnectorError",
    "SentinelDataError",
    "SentinelNetworkError",
    "setup_logging",
]

__version__ = "1.0.0"
