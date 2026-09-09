from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

class ToolExecutionRequest(BaseModel):
    tool: str = Field(..., description="Nombre de la herramienta (ej: ping, system_metrics, process_list, http_get)")
    params: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Parámetros de la tool. Nombres SRS §8.4 (p.ej. ping.target, "
            "timeout_ms, update_config.config_diff); el agente acepta alias "
            "(host, timeout en segundos, diff/config)."
        ),
    )
    timeout: Optional[float] = Field(
        None,
        description=(
            "Tiempo máximo de espera (segundos) para recibir respuesta del agente. "
            "Si se omite, se usa el timeout efectivo por comando (§8.5: default según "
            "riesgo y override por comando, p.ej. traceroute 90s)."
        ),
    )

    class Config:
        json_schema_extra = {
            "example": {
                "tool": "ping",
                "params": {"target": "8.8.8.8", "count": 3, "timeout_ms": 3000},
                "timeout": 15.0
            }
        }


class ToolExecutionResponse(BaseModel):
    id: str
    agent_id: str
    ok: bool
    tool: str
    result: Optional[Any] = None
    error: Optional[str] = None


class AgentUserInfo(BaseModel):
    user_id: str = ""
    client_id: str = ""


class AgentInfo(BaseModel):
    agent_id: str
    client_name: str
    remote_ip: str
    connected_at: str = ""
    public_key_preview: Optional[str] = None
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    client_id: Optional[str] = None
    hostname: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    arch: Optional[str] = None
    cpu_model: Optional[str] = None
    cpu_logical_cores: Optional[int] = None
    cpu_physical_cores: Optional[int] = None
    cpu_freq_mhz: Optional[float] = None
    ram_total_gb: Optional[float] = None
    disk_total_gb: Optional[float] = None
    firmware_vendor: Optional[str] = None
    firmware_product: Optional[str] = None
    firmware_serial: Optional[str] = None
    firmware_uuid: Optional[str] = None
    agent_version: Optional[str] = None
    inventory_captured_at: Optional[str] = None
    online: bool = False
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    user: Optional[AgentUserInfo] = None
