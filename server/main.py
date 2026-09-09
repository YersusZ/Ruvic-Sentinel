import os
import sys
from contextlib import asynccontextmanager

# Cargar server/.env ANTES de importar los módulos que leen variables de
# entorno en tiempo de importación (connection_manager, controllers,
# command_queue). El resto del entorno gana (override=False), salvo MYSQL_*
# que siempre salen de este archivo si está (lab: uvicorn --reload no pisa
# un MYSQL_PASSWORD viejo de la shell).
_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
try:
    from dotenv import dotenv_values, load_dotenv

    load_dotenv(_ENV_PATH, override=False)
    for _key in (
        "MYSQL_DISABLED",
        "MYSQL_HOST",
        "MYSQL_PORT",
        "MYSQL_USER",
        "MYSQL_PASSWORD",
        "MYSQL_DATABASE",
    ):
        _val = dotenv_values(_ENV_PATH).get(_key)
        if _val is not None:
            os.environ[_key] = _val.strip()
except ImportError:
    pass

# Permitir importar el paquete compartido colsoft_tools (raíz del repo) desde server/
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Importa el router desde tu archivo de rutas (ajusta el path si tu archivo se llama diferente)
from controllers import router as websocket_router
from enrollment import router as enrollment_router
from otlp import router as otlp_router

from colsoft_tools.agent_admin import AGENT_VERSION


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    from lib.agent_store import init_agent_store
    from enrollment import init_enrollment_store

    init_agent_store()
    init_enrollment_store()
    yield


app = FastAPI(
    title="WS Tools Agent Server",
    description="Servidor de Control y API REST para Agentes de Observabilidad y Diagnóstico de Red",
    version=AGENT_VERSION,
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(websocket_router)
app.include_router(enrollment_router)
app.include_router(otlp_router)

if __name__ == "__main__":
    from tls_runtime import load_ssl_settings, run_control_server, start_bootstrap

    settings = load_ssl_settings(strict=True)
    start_bootstrap(settings)
    run_control_server(app, settings)