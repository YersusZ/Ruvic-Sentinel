"""Fecha + rango de horas para consultar logs (GET /api/logs y tools de SO).

Contrato (UTC):
  date=YYYY-MM-DD              → día entero, salvo que vengan horas
  startHour / endHour          → HH, HH:MM o HH:MM:SS sobre `date` (o hoy)
  hour                         → una hora (14 → 14:00:00–14:59:59.999)
  startDate / endDate / since / until → ISO 8601 (inclusive)

Si `date` viene con horas, el proxy GET manda startDate/endDate y no `date`
(RobinLogs: `date` ignora el rango).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from colsoft_tools.protocol import parse_iso

_TIME_KEYS = (
    "date",
    "startDate",
    "endDate",
    "since",
    "until",
    "startHour",
    "endHour",
    "hour",
    "start",
    "end",
)

_SYSLOG_TS = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b"
)
_ISO_IN_TEXT = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}


@dataclass(frozen=True)
class LogWindow:
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    since_raw: Optional[str] = None
    until_raw: Optional[str] = None

    def bounded(self) -> bool:
        return self.start is not None or self.end is not None


def time_kwargs(params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in _TIME_KEYS:
        value = (params or {}).get(key)
        if value is None or value == "":
            continue
        out[key] = value
    return out


def as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_iso_z(dt: datetime) -> str:
    return as_utc(dt).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def to_journalctl(dt: datetime) -> str:
    return as_utc(dt).strftime("%Y-%m-%d %H:%M:%S UTC")


def to_ausearch(dt: datetime) -> Tuple[str, str]:
    local = as_utc(dt).astimezone()
    return local.strftime("%m/%d/%Y"), local.strftime("%H:%M:%S")


def wevtutil_time_query(start: Optional[datetime], end: Optional[datetime]) -> Optional[str]:
    parts: List[str] = []
    if start is not None:
        parts.append(f"@SystemTime>='{to_iso_z(start)}'")
    if end is not None:
        parts.append(f"@SystemTime<='{to_iso_z(end)}'")
    if not parts:
        return None
    return f"*[System[TimeCreated[{' and '.join(parts)}]]]"


def journalctl_time_args(window: LogWindow) -> List[str]:
    extra: List[str] = []
    if window.start is not None:
        extra += ["--since", to_journalctl(window.start)]
    elif window.since_raw:
        extra += ["--since", window.since_raw]
    if window.end is not None:
        extra += ["--until", to_journalctl(window.end)]
    elif window.until_raw:
        extra += ["--until", window.until_raw]
    return extra


def window_fields(window: LogWindow) -> Dict[str, Optional[str]]:
    return {
        "start": to_iso_z(window.start) if window.start else None,
        "end": to_iso_z(window.end) if window.end else None,
    }


def parse_hour(value: Any) -> Optional[Tuple[time, bool]]:
    """Devuelve (hora, whole_hour). whole_hour True si no trajeron minutos."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        hour = int(value)
        if 0 <= hour <= 23:
            return time(hour, 0, 0), True
        return None
    text = str(value).strip()
    if re.fullmatch(r"\d{1,2}", text):
        hour = int(text)
        if 0 <= hour <= 23:
            return time(hour, 0, 0), True
        return None
    m = re.fullmatch(r"(\d{1,2}):(\d{2})(?::(\d{2}))?", text)
    if not m:
        return None
    hour, minute = int(m.group(1)), int(m.group(2))
    second = int(m.group(3) or 0)
    if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
        return None
    return time(hour, minute, second), False


def _parse_date(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _end_of_hour(t: time) -> time:
    return time(t.hour, 59, 59, 999999)


def _combine(day: datetime, t: time) -> datetime:
    return datetime(
        day.year,
        day.month,
        day.day,
        t.hour,
        t.minute,
        t.second,
        t.microsecond,
        tzinfo=timezone.utc,
    )


def _maybe_dt(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return as_utc(value)
    return parse_iso(str(value)) if value not in (None, "") else None


def window_from_params(params: Optional[Dict[str, Any]] = None) -> LogWindow:
    p = params or {}
    start_obj = _maybe_dt(p.get("start"))
    end_obj = _maybe_dt(p.get("end"))
    day = _parse_date(p.get("date"))
    start_date = _maybe_dt(p.get("startDate"))
    end_date = _maybe_dt(p.get("endDate"))
    hour = parse_hour(p.get("hour"))
    start_hour = parse_hour(p.get("startHour") or p.get("start_hour"))
    end_hour = parse_hour(p.get("endHour") or p.get("end_hour"))
    since_raw = p.get("since")
    until_raw = p.get("until")
    since_dt = _maybe_dt(since_raw)
    until_dt = _maybe_dt(until_raw)

    if hour and not start_hour:
        start_hour = (hour[0], True)
        end_hour = (hour[0], True)

    if day is not None:
        start = day
        end = day.replace(hour=23, minute=59, second=59, microsecond=999999)
        if hour:
            start = _combine(day, hour[0])
            end = _combine(day, _end_of_hour(hour[0]))
            return LogWindow(start=start, end=end)
        if start_hour:
            start = _combine(day, start_hour[0])
        if end_hour:
            t, whole = end_hour
            end = _combine(day, _end_of_hour(t) if whole else t)
        elif start_hour and start_hour[1]:
            end = _combine(day, _end_of_hour(start_hour[0]))
        return LogWindow(start=start, end=end)

    start = start_obj or start_date or since_dt
    end = end_obj or end_date or until_dt
    base = start or datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    if start_hour or end_hour:
        if start_hour:
            start = _combine(as_utc(base), start_hour[0])
        if end_hour:
            t, whole = end_hour
            end = _combine(as_utc(base if end is None else end), _end_of_hour(t) if whole else t)
        elif start_hour and start_hour[1]:
            end = _combine(as_utc(start or base), _end_of_hour(start_hour[0]))
        return LogWindow(start=start, end=end)

    since_pass = None if since_dt is not None else (str(since_raw).strip() if since_raw else None)
    until_pass = None if until_dt is not None else (str(until_raw).strip() if until_raw else None)
    return LogWindow(start=start, end=end, since_raw=since_pass, until_raw=until_pass)


def expand_query_window(params: Dict[str, Any]) -> Dict[str, Any]:
    """Traduce date+horas a startDate/endDate para RobinLogs."""
    out = dict(params)
    has_hours = any(out.get(k) not in (None, "") for k in ("startHour", "endHour", "hour"))
    if has_hours:
        window = window_from_params(out)
        if window.start is not None:
            out["startDate"] = to_iso_z(window.start)
        if window.end is not None:
            out["endDate"] = to_iso_z(window.end)
        out.pop("date", None)
    for key in ("startHour", "endHour", "hour", "start_hour", "end_hour"):
        out.pop(key, None)
    return out


def parse_log_line_ts(line: str, *, year: Optional[int] = None) -> Optional[datetime]:
    text = (line or "").strip()
    if not text:
        return None
    iso = _ISO_IN_TEXT.search(text)
    if iso:
        return parse_iso(iso.group(1).replace(" ", "T"))
    m = _SYSLOG_TS.match(text)
    if not m:
        return None
    month = _MONTHS[m.group(1).lower()]
    day = int(m.group(2))
    y = year or datetime.now(timezone.utc).year
    try:
        return datetime(
            y, month, day, int(m.group(3)), int(m.group(4)), int(m.group(5)),
            tzinfo=timezone.utc,
        )
    except ValueError:
        return None


def in_window(ts_value: Any, window: LogWindow, *, line: Optional[str] = None) -> bool:
    if not window.bounded():
        return True
    dt = ts_value if isinstance(ts_value, datetime) else None
    if dt is None and ts_value not in (None, ""):
        dt = parse_iso(str(ts_value)) or parse_log_line_ts(str(ts_value))
    if dt is None and line:
        year = window.start.year if window.start else None
        dt = parse_log_line_ts(line, year=year)
    if dt is None:
        return False
    dt = as_utc(dt)
    if window.start is not None and dt < window.start:
        return False
    if window.end is not None and dt > window.end:
        return False
    return True


def filter_entries(
    entries: Iterable[Dict[str, Any]],
    window: LogWindow,
    *,
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    if not window.bounded():
        rows = list(entries)
        return rows[:limit] if limit is not None else rows
    out: List[Dict[str, Any]] = []
    for rec in entries:
        msg = str(rec.get("message") or rec.get("raw") or rec.get("msg") or "")
        if in_window(rec.get("ts"), window, line=msg):
            out.append(rec)
            if limit is not None and len(out) >= limit:
                break
    return out
