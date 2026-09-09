"""
Buffer en disco para telemetría del agente — SRS §9 (RF-CORE-04) / §15.

El agente genera telemetría y puede estar sin conexión. Este buffer:

  - Disco como fuente de verdad (JSONL). RAM no carga el volumen offline.
  - Capacidad NFR: ≥1 GiB y retención ≥24 h (por defecto 7 días o 1 GiB,
    el que se cumpla primero).
  - Reintento: `flush_to_ws` (fallback si el plano de datos está off) o
    `take`/`restore` hacia OTLP/HTTP (§7.1 / RF-OBS-08).

El buffer es thread-safe (locks) y tolerante a archivos corruptos (salta la
línea rota y continúa).
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from colsoft_tools.protocol import now_iso

DEFAULT_MAX_AGE_DAYS = 7.0
DEFAULT_MAX_FILE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 1024 * 1024 * 1024  # 1 GiB — SRS §15
_STATE_NAME = "buffer.state.json"
_ACTIVE_NAME = "buffer.jsonl"

# (path, byte_offset de la próxima línea no leída)
_QueueItem = Tuple[str, int]


def buffer_from_config(config: Optional[Dict[str, Any]] = None) -> "TelemetryBuffer":
    """Construye el buffer con defaults NFR (§15) si el config no los pone."""
    tb = (config or {}).get("telemetry_buffer") if isinstance(config, dict) else None
    tb = tb if isinstance(tb, dict) else {}
    max_events = tb.get("max_events")
    return TelemetryBuffer(
        tb.get("dir"),
        max_events=int(max_events) if max_events not in (None, "") else 0,
        max_age_days=float(tb.get("max_age_days") or DEFAULT_MAX_AGE_DAYS),
        max_file_bytes=int(tb.get("max_file_bytes") or DEFAULT_MAX_FILE_BYTES),
        max_total_bytes=int(tb.get("max_total_bytes") or DEFAULT_MAX_TOTAL_BYTES),
    )


def _count_lines(path: str, skip_bytes: int = 0) -> int:
    n = 0
    try:
        with open(path, "rb") as f:
            if skip_bytes:
                f.seek(skip_bytes)
            for line in f:
                if line.strip():
                    n += 1
    except OSError:
        return 0
    return n


def _parse_line(raw: bytes) -> Optional[Dict[str, Any]]:
    line = raw.decode("utf-8", errors="replace").strip()
    if not line:
        return None
    try:
        ev = json.loads(line)
    except ValueError:
        return None
    return ev if isinstance(ev, dict) else None


class TelemetryBuffer:
    """Cola FIFO persistente de eventos de telemetría (disco + cursor)."""

    def __init__(
        self,
        dir_path: Optional[str] = None,
        *,
        max_events: int = 0,
        max_age_days: float = DEFAULT_MAX_AGE_DAYS,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    ):
        self.dir_path = os.path.expanduser(
            dir_path or os.path.join("results_logs", "telemetry_buffer")
        )
        os.makedirs(self.dir_path, exist_ok=True)
        # 0 = sin tope por conteo (el tope real es max_total_bytes / edad).
        self.max_events = max(0, int(max_events))
        self.max_age_days = max(1.0, float(max_age_days))
        self.max_file_bytes = max(1024, int(max_file_bytes))
        self.max_total_bytes = max(self.max_file_bytes, int(max_total_bytes))

        self._lock = threading.Lock()
        self._active_file = os.path.join(self.dir_path, _ACTIVE_NAME)
        self._state_file = os.path.join(self.dir_path, _STATE_NAME)
        self._queue: List[_QueueItem] = []
        self._pending = 0
        self._load_state()

    def _load_state(self) -> None:
        state = None
        try:
            with open(self._state_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                state = raw
        except (OSError, ValueError):
            state = None

        queue: List[_QueueItem] = []
        if state and isinstance(state.get("queue"), list):
            for item in state["queue"]:
                if not isinstance(item, dict):
                    continue
                path = item.get("path")
                if not isinstance(path, str) or not os.path.isfile(path):
                    continue
                try:
                    offset = max(0, int(item.get("offset") or 0))
                except (TypeError, ValueError):
                    offset = 0
                try:
                    if offset > os.path.getsize(path):
                        offset = 0
                except OSError:
                    continue
                queue.append((path, offset))
        elif state and isinstance(state.get("files"), list):
            # Compat con el estado {files, offset} de un arranque mixto.
            offset0 = 0
            try:
                offset0 = max(0, int(state.get("offset") or 0))
            except (TypeError, ValueError):
                offset0 = 0
            for i, path in enumerate(state["files"]):
                if isinstance(path, str) and os.path.isfile(path):
                    queue.append((path, offset0 if i == 0 else 0))

        if not queue:
            queue = [(p, 0) for p in self._discover_files()]

        self._queue = queue
        self._pending = sum(_count_lines(p, off) for p, off in self._queue)
        self._write_state()

    def _discover_files(self) -> List[str]:
        names: List[str] = []
        try:
            for fname in os.listdir(self.dir_path):
                if not fname.endswith(".jsonl"):
                    continue
                names.append(fname)
        except OSError:
            return []
        restores = sorted(n for n in names if n.startswith("buffer.restore."))
        rotated = sorted(
            n
            for n in names
            if n.startswith("buffer.")
            and not n.startswith("buffer.restore.")
            and n != _ACTIVE_NAME
        )
        ordered = restores + rotated
        if _ACTIVE_NAME in names:
            ordered.append(_ACTIVE_NAME)
        return [os.path.join(self.dir_path, n) for n in ordered]

    def _write_state(self) -> None:
        payload = {
            "queue": [{"path": p, "offset": off} for p, off in self._queue],
            "pending": self._pending,
        }
        tmp = f"{self._state_file}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._state_file)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass

    def _total_bytes(self) -> int:
        size = 0
        for path, _off in self._queue:
            try:
                size += os.path.getsize(path)
            except OSError:
                continue
        return size

    def _rotate_if_needed(self) -> None:
        try:
            if not os.path.isfile(self._active_file):
                return
            if os.path.getsize(self._active_file) < self.max_file_bytes:
                return
        except OSError:
            return
        ts = time.strftime("%Y%m%d%H%M%S", time.gmtime())
        rotated = os.path.join(self.dir_path, f"buffer.{ts}.jsonl")
        n = 0
        while os.path.exists(rotated):
            n += 1
            rotated = os.path.join(self.dir_path, f"buffer.{ts}-{n}.jsonl")
        try:
            os.replace(self._active_file, rotated)
        except OSError:
            return
        self._queue = [
            (rotated if p == self._active_file else p, off) for p, off in self._queue
        ]

    def _prune(self) -> None:
        cutoff = time.time() - self.max_age_days * 86400
        changed = True
        while changed:
            changed = False
            for path, off in list(self._queue):
                if path == self._active_file:
                    continue
                try:
                    stale = os.path.getmtime(path) < cutoff
                except OSError:
                    stale = True
                if stale:
                    self._drop_path(path)
                    changed = True

        while self._total_bytes() > self.max_total_bytes and self._queue:
            path, _off = self._queue[0]
            self._drop_path(path)

        if self.max_events > 0:
            while self._pending > self.max_events and self._queue:
                path, _off = self._queue[0]
                self._drop_path(path)

    def _drop_path(self, path: str) -> None:
        remaining: List[_QueueItem] = []
        for p, off in self._queue:
            if p == path:
                self._pending = max(0, self._pending - _count_lines(p, off))
            else:
                remaining.append((p, off))
        self._queue = remaining
        try:
            os.remove(path)
        except OSError:
            pass

    def _append_line(self, event: Dict[str, Any]) -> None:
        try:
            with open(self._active_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            return
        if not any(p == self._active_file for p, _off in self._queue):
            self._queue.append((self._active_file, 0))

    def put(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Encola un evento en disco respetando retención y tope de bytes."""
        rec = dict(event or {})
        if not rec.get("ts"):
            rec["ts"] = now_iso()
        with self._lock:
            self._append_line(rec)
            self._pending += 1
            self._rotate_if_needed()
            self._prune()
            self._write_state()
        return rec

    def pending(self) -> List[Dict[str, Any]]:
        """Hasta 256 eventos del frente (debug). No consume la cola."""
        with self._lock:
            return self._read_front(256, consume=False)

    def count(self) -> int:
        with self._lock:
            return int(self._pending)

    def take(self, n: int) -> List[Dict[str, Any]]:
        """Saca hasta `n` eventos del frente (FIFO). `restore` si el envío falla."""
        n = max(0, int(n))
        with self._lock:
            batch = self._read_front(n, consume=True)
            self._write_state()
            return batch

    def restore(self, events: List[Dict[str, Any]]) -> None:
        """Reencola al frente eventos que no se pudieron exportar."""
        if not events:
            return
        ts = time.strftime("%Y%m%d%H%M%S", time.gmtime())
        path = os.path.join(self.dir_path, f"buffer.restore.{ts}.jsonl")
        n = 0
        while os.path.exists(path):
            n += 1
            path = os.path.join(self.dir_path, f"buffer.restore.{ts}-{n}.jsonl")
        try:
            with open(path, "w", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev, ensure_ascii=False, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            return
        with self._lock:
            self._queue.insert(0, (path, 0))
            self._pending += len(events)
            self._prune()
            self._write_state()

    def clear(self) -> None:
        with self._lock:
            for path, _off in list(self._queue):
                try:
                    os.remove(path)
                except OSError:
                    pass
            try:
                os.remove(self._state_file)
            except OSError:
                pass
            self._queue = []
            self._pending = 0

    async def flush_to_ws(self, send: Callable[[Dict[str, Any]], Any]) -> int:
        """Drena el buffer sobre el WebSocket (reintento al reconectar).

        `send` recibe el dict del evento y debe lanzar en caso de error; solo
        se eliminan del buffer los eventos que `send` confirmó (sin excepción).
        """
        sent = 0
        while True:
            batch = self.take(1)
            if not batch:
                break
            try:
                await send(batch[0])
            except Exception:
                self.restore(batch)
                break
            sent += 1
        return sent

    def _read_front(self, n: int, *, consume: bool) -> List[Dict[str, Any]]:
        if n <= 0 or not self._queue:
            return []
        batch: List[Dict[str, Any]] = []
        q = list(self._queue)
        pending_taken = 0

        while len(batch) < n and q:
            path, offset = q[0]
            try:
                with open(path, "rb") as f:
                    if offset:
                        f.seek(offset)
                    eof = False
                    while len(batch) < n:
                        raw = f.readline()
                        if not raw:
                            eof = True
                            break
                        ev = _parse_line(raw)
                        if ev is None:
                            if consume:
                                q[0] = (path, f.tell())
                            continue
                        batch.append(ev)
                        if consume:
                            q[0] = (path, f.tell())
                            pending_taken += 1
                    if consume and eof:
                        q.pop(0)
                        if path != self._active_file:
                            try:
                                os.remove(path)
                            except OSError:
                                pass
                        else:
                            try:
                                open(path, "wb").close()
                            except OSError:
                                pass
            except OSError:
                if consume:
                    q.pop(0)
                else:
                    break

            if not consume:
                # peek: avanzar al siguiente archivo sin mutar cola real
                q.pop(0)
                continue

        if consume:
            self._queue = q
            self._pending = max(0, self._pending - pending_taken)
        return batch
