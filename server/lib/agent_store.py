"""Inventario MySQL vía SQLAlchemy: `users` (Ruvic) + `agents` (ficha del host).

Requiere `MYSQL_HOST` (o `AGENT_STORE_URL` en tests). `MYSQL_DISABLED=1` apaga
el inventario sin borrar el resto de `MYSQL_*`. No guarda PEM ni JWT.
El dueño sale de GET a Ruvic. El hardware se refresca en cada conexión
(mismo `agent_id`: UPDATE, no un registro nuevo).
"""

from __future__ import annotations

import logging
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy import Float, Index, Integer, String, create_engine, func, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)
from sqlalchemy.pool import StaticPool

logger = logging.getLogger("agent-server")

_lock = threading.Lock()
_warned_no_mysql = False
_engine: Optional[Engine] = None
_SessionLocal: Optional[sessionmaker] = None

_AGENT_COLUMNS = (
    "agent_id",
    "user_id",
    "client_id",
    "client_name",
    "tenant_id",
    "remote_ip",
    "hostname",
    "os_name",
    "os_version",
    "arch",
    "cpu_model",
    "cpu_logical_cores",
    "cpu_physical_cores",
    "cpu_freq_mhz",
    "ram_total_gb",
    "disk_total_gb",
    "firmware_vendor",
    "firmware_product",
    "firmware_serial",
    "firmware_uuid",
    "agent_version",
    "inventory_captured_at",
    "first_seen",
    "last_seen",
)

_USER_COLUMNS = (
    "user_id",
    "client_id",
    "first_seen",
    "last_seen",
)

_AGENT_MIGRATIONS = (
    ("user_id", "VARCHAR(128) NOT NULL DEFAULT ''"),
    ("client_id", "VARCHAR(128) NOT NULL DEFAULT ''"),
    ("os_version", "VARCHAR(255) NOT NULL DEFAULT ''"),
    ("arch", "VARCHAR(64) NOT NULL DEFAULT ''"),
    ("cpu_model", "VARCHAR(255) NOT NULL DEFAULT ''"),
    ("cpu_logical_cores", "INT NULL"),
    ("cpu_physical_cores", "INT NULL"),
    ("cpu_freq_mhz", "DOUBLE NULL"),
    ("ram_total_gb", "DOUBLE NULL"),
    ("disk_total_gb", "DOUBLE NULL"),
    ("firmware_vendor", "VARCHAR(255) NOT NULL DEFAULT ''"),
    ("firmware_product", "VARCHAR(255) NOT NULL DEFAULT ''"),
    ("firmware_serial", "VARCHAR(255) NOT NULL DEFAULT ''"),
    ("firmware_uuid", "VARCHAR(128) NOT NULL DEFAULT ''"),
    ("inventory_captured_at", "VARCHAR(40) NOT NULL DEFAULT ''"),
)

_USER_DROP_COLUMNS = ("email", "display_name")

_STR_KEYS = (
    "user_id",
    "client_id",
    "client_name",
    "tenant_id",
    "remote_ip",
    "hostname",
    "os_name",
    "os_version",
    "arch",
    "cpu_model",
    "firmware_vendor",
    "firmware_product",
    "firmware_serial",
    "firmware_uuid",
    "agent_version",
    "inventory_captured_at",
)
_NUM_KEYS = (
    "cpu_logical_cores",
    "cpu_physical_cores",
    "cpu_freq_mhz",
    "ram_total_gb",
    "disk_total_gb",
)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    __table_args__ = (Index("idx_users_client", "client_id"),)

    user_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(128), default="")
    first_seen: Mapped[str] = mapped_column(String(40))
    last_seen: Mapped[str] = mapped_column(String(40))


class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (
        Index("idx_agents_user", "user_id"),
        Index("idx_agents_client", "client_id"),
    )

    agent_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(128), default="")
    client_id: Mapped[str] = mapped_column(String(128), default="")
    client_name: Mapped[str] = mapped_column(String(255), default="")
    tenant_id: Mapped[str] = mapped_column(String(128), default="")
    remote_ip: Mapped[str] = mapped_column(String(64), default="")
    hostname: Mapped[str] = mapped_column(String(255), default="")
    os_name: Mapped[str] = mapped_column(String(128), default="")
    os_version: Mapped[str] = mapped_column(String(255), default="")
    arch: Mapped[str] = mapped_column(String(64), default="")
    cpu_model: Mapped[str] = mapped_column(String(255), default="")
    cpu_logical_cores: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cpu_physical_cores: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cpu_freq_mhz: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ram_total_gb: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    disk_total_gb: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    firmware_vendor: Mapped[str] = mapped_column(String(255), default="")
    firmware_product: Mapped[str] = mapped_column(String(255), default="")
    firmware_serial: Mapped[str] = mapped_column(String(255), default="")
    firmware_uuid: Mapped[str] = mapped_column(String(128), default="")
    agent_version: Mapped[str] = mapped_column(String(64), default="")
    inventory_captured_at: Mapped[str] = mapped_column(String(40), default="")
    first_seen: Mapped[str] = mapped_column(String(40))
    last_seen: Mapped[str] = mapped_column(String(40))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mysql_disabled() -> bool:
    return (os.getenv("MYSQL_DISABLED") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def mysql_configured() -> bool:
    if _mysql_disabled():
        return False
    return bool(
        (os.getenv("MYSQL_HOST") or os.getenv("AGENT_STORE_URL") or "").strip()
    )


def _note_store_off() -> None:
    global _warned_no_mysql
    if _warned_no_mysql:
        return
    _warned_no_mysql = True
    if _mysql_disabled():
        logger.info("inventario MySQL desactivado (MYSQL_DISABLED=1)")
    else:
        logger.warning("MYSQL_HOST no definido; inventario desactivado")


def _parse_mysql_host_port(
    raw_host: Optional[str] = None, raw_port: Optional[str] = None
) -> Tuple[str, int]:
    """MYSQL_HOST puede venir como URL (`mysql://user@host:3306/db` o `https://host/`)."""
    host = (raw_host if raw_host is not None else os.getenv("MYSQL_HOST") or "127.0.0.1").strip()
    port_s = (raw_port if raw_port is not None else os.getenv("MYSQL_PORT") or "").strip()
    parsed_port: Optional[int] = None
    if "://" in host or host.startswith("//"):
        parsed = urlparse(host if "://" in host else f"//{host}")
        host = (parsed.hostname or "").strip() or host
        if parsed.port:
            parsed_port = int(parsed.port)
    host = host.rstrip("/").split("/")[0].strip() or "127.0.0.1"
    if host in ("localhost", "::1"):
        host = "127.0.0.1"
    if parsed_port is not None:
        return host, parsed_port
    try:
        return host, int(port_s) if port_s else 3306
    except ValueError:
        return host, 3306


def _mysql_credentials() -> Tuple[str, str, str]:
    """user, password, database — admite credenciales embebidas en MYSQL_HOST (mysql://…)."""
    raw_host = (os.getenv("MYSQL_HOST") or "").strip()
    user = (os.getenv("MYSQL_USER") or "").strip()
    password = os.getenv("MYSQL_PASSWORD") or ""
    database = (os.getenv("MYSQL_DATABASE") or "robin_agents").strip()

    if "://" in raw_host:
        parsed = urlparse(raw_host)
        if parsed.username:
            user = parsed.username
        if parsed.password:
            password = parsed.password
        path_db = (parsed.path or "").strip("/").split("/")[0].strip()
        if path_db:
            database = path_db

    if not user:
        user = "robin"
    return user, password, database


def _mysql_connect_args() -> Dict[str, Any]:
    """TCP explícito: `localhost` usa socket y MySQL autentica `user@localhost`."""
    host, port = _parse_mysql_host_port()
    user, password, database = _mysql_credentials()
    return {
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "database": database,
        "charset": "utf8mb4",
    }


def _database_url() -> str:
    explicit = (os.getenv("AGENT_STORE_URL") or "").strip()
    if explicit:
        return explicit
    # Host/puerto van en connect_args. Meter un https:// en la URL hace
    # que SQLAlchemy haga int('') al parsear el puerto.
    return "mysql+pymysql://"


def _migrate(engine: Engine) -> None:
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    if "agents" in tables:
        cols = {c["name"] for c in insp.get_columns("agents")}
        for name, spec in _AGENT_MIGRATIONS:
            if name in cols:
                continue
            try:
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE agents ADD COLUMN {name} {spec}"))
            except Exception as e:
                logger.warning("migración agents.%s: %s", name, e)
    if "users" in tables:
        user_cols = {c["name"] for c in insp.get_columns("users")}
        for name in _USER_DROP_COLUMNS:
            if name not in user_cols:
                continue
            try:
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE users DROP COLUMN {name}"))
            except Exception as e:
                logger.warning("migración users DROP %s: %s", name, e)


def _get_engine() -> Optional[Engine]:
    global _engine, _SessionLocal, _warned_no_mysql
    if not mysql_configured():
        _note_store_off()
        return None
    if _engine is None:
        url = _database_url()
        kwargs: Dict[str, Any] = {}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            kwargs["poolclass"] = StaticPool
        else:
            kwargs["pool_pre_ping"] = True
            kwargs["pool_recycle"] = 3600
            kwargs["connect_args"] = _mysql_connect_args()
        engine = create_engine(url, **kwargs)
        try:
            Base.metadata.create_all(engine)
            _migrate(engine)
        except Exception:
            engine.dispose()
            raise
        _engine = engine
        _SessionLocal = sessionmaker(
            bind=_engine, expire_on_commit=False, autoflush=False
        )
        if not url.startswith("sqlite"):
            logger.info(
                "inventario MySQL listo db=%s user=%s host=%s",
                kwargs.get("connect_args", {}).get("database"),
                kwargs.get("connect_args", {}).get("user"),
                kwargs.get("connect_args", {}).get("host"),
            )
    return _engine


def init_agent_store() -> None:
    """Crea tablas al arrancar. Falla en log, no tumba el API."""
    if not mysql_configured():
        _note_store_off()
        return
    try:
        _get_engine()
    except Exception as e:
        logger.warning("inventario MySQL no disponible al arrancar: %s", e)


def reset_agent_store() -> None:
    global _engine, _SessionLocal, _warned_no_mysql
    _warned_no_mysql = False
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


def _row_to_dict(row: Any, columns: tuple) -> Dict[str, Any]:
    if row is None:
        return {}
    return {k: getattr(row, k) for k in columns}


@contextmanager
def _session() -> Iterator[Optional[Session]]:
    if _get_engine() is None or _SessionLocal is None:
        yield None
        return
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _keep_str(new: Optional[str], old: Any) -> str:
    val = (new or "").strip() if new is not None else ""
    if val:
        return val
    return str(old or "")


def _keep_num(new: Any, old: Any):
    if new is None or new == "":
        return old
    if isinstance(new, bool):
        return old
    return new


def _as_int(raw: Any) -> Optional[int]:
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _as_float(raw: Any) -> Optional[float]:
    if raw is None or raw == "":
        return None
    try:
        n = float(raw)
    except (TypeError, ValueError):
        return None
    if n != n:  # NaN
        return None
    return n


def _bytes_to_gb(raw: Any) -> Optional[float]:
    n = _as_float(raw)
    if n is None or n <= 0:
        return None
    return round(n / (1024.0 ** 3), 2)


def snapshot_from_hardware(result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Campos estáticos desde `hardware_inventory` (se refrescan al reconectar)."""
    if not isinstance(result, dict):
        return {}
    cpu = result.get("cpu") if isinstance(result.get("cpu"), dict) else {}
    mem = result.get("memory") if isinstance(result.get("memory"), dict) else {}
    firmware = result.get("firmware") if isinstance(result.get("firmware"), dict) else {}
    freq = cpu.get("freq") if isinstance(cpu.get("freq"), dict) else {}
    mhz = freq.get("max_mhz") or freq.get("current_mhz")
    disks = result.get("disks") if isinstance(result.get("disks"), list) else []
    seen_dev: Dict[str, int] = {}
    for disk in disks:
        if not isinstance(disk, dict):
            continue
        tot = disk.get("total")
        try:
            tot_i = int(tot)
        except (TypeError, ValueError):
            continue
        key = str(disk.get("device") or disk.get("mountpoint") or len(seen_dev))
        if key not in seen_dev:
            seen_dev[key] = tot_i
    disk_bytes = sum(seen_dev.values()) if seen_dev else 0
    out: Dict[str, Any] = {
        "hostname": (result.get("hostname") or "").strip() or None,
        "os_name": (result.get("os") or "").strip() or None,
        "os_version": (result.get("os_version") or "").strip() or None,
        "arch": (result.get("arch") or "").strip() or None,
        "cpu_model": (cpu.get("model") or "").strip() or None,
        "cpu_logical_cores": _as_int(cpu.get("logical_cores")),
        "cpu_physical_cores": _as_int(cpu.get("physical_cores")),
        "cpu_freq_mhz": _as_float(mhz),
        "ram_total_gb": _bytes_to_gb(mem.get("total")),
        "disk_total_gb": _bytes_to_gb(disk_bytes) if disk_bytes else None,
        "firmware_vendor": (firmware.get("vendor") or "").strip() or None,
        "firmware_product": (firmware.get("product") or "").strip() or None,
        "firmware_serial": (firmware.get("serial") or "").strip() or None,
        "firmware_uuid": (firmware.get("uuid") or "").strip() or None,
    }
    return {k: v for k, v in out.items() if v is not None and v != ""}


def snapshot_from_health(result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(result, dict):
        return {}
    version = str(result.get("version") or "").strip()
    return {"agent_version": version} if version else {}


def upsert_user(
    user_id: str,
    *,
    client_id: Optional[str] = None,
) -> Dict[str, Any]:
    user_id = (user_id or "").strip()
    if not user_id:
        raise ValueError("user_id requerido")
    now = _now()
    with _lock:
        with _session() as session:
            if session is None:
                return {
                    "user_id": user_id,
                    "client_id": (client_id or "").strip(),
                    "first_seen": now,
                    "last_seen": now,
                }
            row = session.get(User, user_id)
            if row is None:
                row = User(
                    user_id=user_id,
                    client_id=(client_id or "").strip(),
                    first_seen=now,
                    last_seen=now,
                )
                session.add(row)
            else:
                row.client_id = _keep_str(client_id, row.client_id)
                row.last_seen = now
            session.flush()
            return _row_to_dict(row, _USER_COLUMNS)


def get_user(user_id: str) -> Optional[Dict[str, Any]]:
    user_id = (user_id or "").strip()
    if not user_id:
        return None
    with _lock:
        with _session() as session:
            if session is None:
                return None
            row = session.get(User, user_id)
            return _row_to_dict(row, _USER_COLUMNS) if row else None


def upsert_agent(agent_id: str, **fields: Any) -> Dict[str, Any]:
    """Inserta o actualiza. Strings/números vacíos no pisan un valor ya guardado."""
    agent_id = (agent_id or "").strip()
    if not agent_id:
        raise ValueError("agent_id requerido")
    now = _now()
    with _lock:
        with _session() as session:
            if session is None:
                values = {k: "" for k in _AGENT_COLUMNS}
                values["agent_id"] = agent_id
                values["first_seen"] = now
                values["last_seen"] = now
                for key in _STR_KEYS:
                    if fields.get(key) is not None:
                        values[key] = str(fields[key]).strip()
                for key in _NUM_KEYS:
                    values[key] = fields.get(key)
                return values
            row = session.get(Agent, agent_id)
            if row is None:
                kwargs: Dict[str, Any] = {
                    "agent_id": agent_id,
                    "first_seen": now,
                    "last_seen": now,
                }
                for key in _STR_KEYS:
                    kwargs[key] = (
                        str(fields[key]).strip() if fields.get(key) is not None else ""
                    ) or ""
                for key in _NUM_KEYS:
                    kwargs[key] = fields.get(key)
                row = Agent(**kwargs)
                session.add(row)
            else:
                for key in _STR_KEYS:
                    setattr(row, key, _keep_str(fields.get(key), getattr(row, key)))
                for key in _NUM_KEYS:
                    setattr(row, key, _keep_num(fields.get(key), getattr(row, key)))
                row.last_seen = now
            session.flush()
            return _row_to_dict(row, _AGENT_COLUMNS)


def apply_tool_snapshot(
    agent_id: str, tool: str, result: Optional[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Aplica hardware_inventory / health_check sobre el mismo registro.

    `hardware_inventory` actualiza la ficha en cada captura (RAM, CPU, disco…).
    `system_metrics` solo rellena si aún no hubo inventario de hardware.
    """
    if not mysql_configured():
        return None
    tool = (tool or "").strip()
    if isinstance(result, dict) and str(result.get("status") or "").upper() == "ERROR":
        return get_agent(agent_id)
    fields: Dict[str, Any] = {}
    if tool == "hardware_inventory":
        fields = snapshot_from_hardware(result)
        if fields:
            fields["inventory_captured_at"] = _now()
    elif tool == "health_check":
        fields = snapshot_from_health(result)
    elif tool == "system_metrics":
        agent = get_agent(agent_id) or {}
        if str(agent.get("inventory_captured_at") or "").strip():
            return agent
        fields = snapshot_from_hardware(
            {
                "hostname": (result or {}).get("hostname"),
                "os": (result or {}).get("os"),
                "os_version": (result or {}).get("os_version"),
                "arch": (result or {}).get("arch"),
                "cpu": (result or {}).get("cpu"),
                "memory": (result or {}).get("memory"),
                "disks": (result or {}).get("disks") or (result or {}).get("volumes"),
                "firmware": (result or {}).get("firmware"),
            }
        )
    if not fields:
        return get_agent(agent_id)
    return upsert_agent(agent_id, **fields)


def needs_static_inventory(agent_id: str) -> bool:
    """True en cada conexión si MySQL está activo (refresco, no alta duplicada)."""
    if not mysql_configured():
        return False
    return bool((agent_id or "").strip())


def get_agent(agent_id: str) -> Optional[Dict[str, Any]]:
    agent_id = (agent_id or "").strip()
    if not agent_id:
        return None
    with _lock:
        with _session() as session:
            if session is None:
                return None
            row = session.get(Agent, agent_id)
            return _row_to_dict(row, _AGENT_COLUMNS) if row else None


def list_agents(
    *,
    user_id: Optional[str] = None,
    client_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    with _lock:
        with _session() as session:
            if session is None:
                return []
            q = select(Agent)
            if user_id:
                q = q.where(Agent.user_id == user_id.strip())
            if client_id:
                q = q.where(Agent.client_id == client_id.strip())
            q = q.order_by(Agent.last_seen.desc())
            rows = session.scalars(q).all()
            return [_row_to_dict(row, _AGENT_COLUMNS) for row in rows]


def count_stored_agents() -> int:
    """Total de filas en `agents` (health / diagnóstico)."""
    with _lock:
        with _session() as session:
            if session is None:
                return 0
            return int(session.scalar(select(func.count()).select_from(Agent)) or 0)
