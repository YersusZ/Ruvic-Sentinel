import os
import json
from datetime import datetime
import logging

logger = logging.getLogger("agent-server")

RESULTS_DIR = "results_logs"
os.makedirs(RESULTS_DIR, exist_ok=True)

def save_execution_result_to_json(agent_id: str, payload: dict) -> str:
    """
    Guarda la respuesta enviada por el cliente en un archivo JSON local.
    Organiza por ID del agente y estampa de tiempo.
    """
    try:
        now = datetime.now()
        timestamp_str = now.strftime("%Y%m%d_%H%M%S_%f")
        tool_name = (
            payload.get("tool")
            or (payload.get("event") or {}).get("tool")
            or "unknown_tool"
        )
        req_id = (
            payload.get("message_id")
            or payload.get("request_id")
            or payload.get("id")
            or "no_id"
        )

        # Nombre único para el archivo JSON
        filename = f"{agent_id}_{tool_name}_{timestamp_str}.json"
        
        # Opcional: Crear subcarpeta por cliente/agente
        agent_dir = os.path.join(RESULTS_DIR, agent_id)
        os.makedirs(agent_dir, exist_ok=True)
        
        filepath = os.path.join(agent_dir, filename)

        # Contenido enriquecido con metadatos del servidor
        record = {
            "agent_id": agent_id,
            "received_at": now.isoformat(),
            "execution_type": "scheduled" if str(req_id).startswith("auto-") else "manual",
            "request_id": req_id,
            "data": payload
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, ensure_ascii=False)

        logger.info(f"[SERVER LOG] Resultado de '{tool_name}' (ID: {req_id}) guardado en: {filepath}")
        return filepath

    except Exception as e:
        logger.error(f"[SERVER ERROR] Error al guardar JSON localmente: {e}")
        return ""