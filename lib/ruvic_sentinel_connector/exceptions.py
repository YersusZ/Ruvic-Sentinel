"""Excepciones propias del conector Ruvic Sentinel."""


class SentinelConnectorError(Exception):
    """Error base del conector."""


class SentinelAuthError(SentinelConnectorError):
    """JWT inválido, expirado o sin permiso (HTTP 401/403)."""


class SentinelNetworkError(SentinelConnectorError):
    """No se alcanzó el plano de control (host, TLS, timeout)."""


class SentinelDataError(SentinelConnectorError):
    """La petición es válida pero el recurso no existe o el payload es inválido."""
