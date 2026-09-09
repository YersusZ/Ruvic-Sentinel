# Pegar en /workspace/project/Dockerfile (hermano de ws_client/).
#
# Build context (subir a mano al project de Robin; no están en git):
#   ws_client/certs/server/signing.key
#
# Runtime (montar en el pod Robin; NO van en la imagen):
#   ca.key + ca.crt  →  /certs/enrollment/   (POST /api/enroll)
#   results_logs/    →  /app/server/results_logs/  (tokens JSONL)
#
# Generar CA: python scripts/enroll.py --server-only --out-dir ./certs --san <host-ingress>
#
# Plantilla env panel: ws_client/server/.env.robin-ingress
# Guía: ws_client/docs/robin-plataforma-agentes.md
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    SERVER_SIGNING_KEY=/certs/signing.key \
    ENROLLMENT_CA_KEY=/certs/enrollment/ca.key \
    ENROLLMENT_CA_CERT=/certs/enrollment/ca.crt \
    ENROLL_DIR=results_logs \
    ENROLLMENT_TOKENS_FILE=results_logs/enrollment_tokens.jsonl \
    ENROLLMENT_TOKENS_AUTO_APPEND=1 \
    ENROLLMENT_BOOTSTRAP_PORT=0

WORKDIR /app

COPY ws_client/server/requirements.txt /app/server/requirements.txt
RUN pip install --no-cache-dir -r /app/server/requirements.txt

COPY ws_client/colsoft_tools/__init__.py /app/colsoft_tools/__init__.py
COPY ws_client/colsoft_tools/agent_admin.py /app/colsoft_tools/agent_admin.py
COPY ws_client/colsoft_tools/cloud_metadata.py /app/colsoft_tools/cloud_metadata.py
COPY ws_client/colsoft_tools/config_manager.py /app/colsoft_tools/config_manager.py
COPY ws_client/colsoft_tools/data_plane.py /app/colsoft_tools/data_plane.py
COPY ws_client/colsoft_tools/endpoint_security.py /app/colsoft_tools/endpoint_security.py
COPY ws_client/colsoft_tools/event_model.py /app/colsoft_tools/event_model.py
COPY ws_client/colsoft_tools/linux_collectors.py /app/colsoft_tools/linux_collectors.py
COPY ws_client/colsoft_tools/log_range.py /app/colsoft_tools/log_range.py
COPY ws_client/colsoft_tools/network_checks.py /app/colsoft_tools/network_checks.py
COPY ws_client/colsoft_tools/observability.py /app/colsoft_tools/observability.py
COPY ws_client/colsoft_tools/protocol.py /app/colsoft_tools/protocol.py
COPY ws_client/colsoft_tools/security.py /app/colsoft_tools/security.py
COPY ws_client/colsoft_tools/self_update.py /app/colsoft_tools/self_update.py
COPY ws_client/colsoft_tools/tamper.py /app/colsoft_tools/tamper.py
COPY ws_client/colsoft_tools/telemetry_buffer.py /app/colsoft_tools/telemetry_buffer.py
COPY ws_client/colsoft_tools/tls_util.py /app/colsoft_tools/tls_util.py
COPY ws_client/colsoft_tools/tool_catalog.py /app/colsoft_tools/tool_catalog.py
COPY ws_client/colsoft_tools/windows_collectors.py /app/colsoft_tools/windows_collectors.py

COPY ws_client/server/main.py /app/server/main.py
COPY ws_client/server/healthcheck.py /app/server/healthcheck.py
COPY ws_client/server/controllers.py /app/server/controllers.py
COPY ws_client/server/connection_manager.py /app/server/connection_manager.py
COPY ws_client/server/command_queue.py /app/server/command_queue.py
COPY ws_client/server/models.py /app/server/models.py
COPY ws_client/server/enrollment.py /app/server/enrollment.py
COPY ws_client/server/otlp.py /app/server/otlp.py
COPY ws_client/server/tls_runtime.py /app/server/tls_runtime.py
COPY ws_client/server/save_result.py /app/server/save_result.py
COPY ws_client/server/lib/agent_store.py /app/server/lib/agent_store.py
COPY ws_client/server/lib/jwt_auth.py /app/server/lib/jwt_auth.py
COPY ws_client/server/lib/metrics_logger.py /app/server/lib/metrics_logger.py
COPY ws_client/server/lib/ruvic_user.py /app/server/lib/ruvic_user.py
COPY ws_client/server/lib/cve_correlator.py /app/server/lib/cve_correlator.py

# signing.key en imagen (build). ca.key/ca.crt se montan en el pod (ver comentario arriba).
COPY ws_client/certs/server/signing.key /tmp/signing.key
RUN mkdir -p /certs/enrollment /app/server/results_logs \
    && mv /tmp/signing.key /certs/signing.key \
    && chmod 600 /certs/signing.key \
    && test -s /certs/signing.key

WORKDIR /app/server

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "healthcheck.py"]

CMD ["python", "main.py"]
