# Documentación

Índice de este directorio. El README de la raíz describe cómo correr agente y
servidor; aquí está el producto y las integraciones Robin.

Guía de **catálogo Ruvic** (ocho secciones, bilingüe): [`index.html`](index.html) + [`../manifest.json`](../manifest.json).

Product docs (Mintlify) live in `ruvic-documentation`, **Ruvic Sentinel**:

- Install and enroll: `site/ruvic/usage/endpoint-agents/install.mdx`
- Identity and folders: `site/ruvic/usage/endpoint-agents/identity.mdx`
- TLS / Ed25519 errors: `site/ruvic/usage/endpoint-agents/troubleshooting.mdx`

| Documento | Qué es |
|---|---|
| [checklist-pendiente.md](checklist-pendiente.md) | Estado vs SRS (qué está hecho) |
| [robin-plataforma-agentes.md](robin-plataforma-agentes.md) | **Robin prod:** enrollment, conexión WSS/OTLP, multi-tenant |
| [produccion.md](produccion.md) | JWT, mTLS y checklist de producción |
| [agent-telemetry.md](agent-telemetry.md) | Telemetry taxonomy for **this** agent |
| [telemetry-json-rdo.md](telemetry-json-rdo.md) | Ingest JSON **and** report widgets (OTLP `points[]`, load average) |
| [empaquetado.md](empaquetado.md) | §16: MSI/deb/rpm, firma, enrollment, silencioso, ARM64 |
| [cumplimiento.md](cumplimiento.md) | §18: trazabilidad ISO 27001 / CIS / SFC |
| [instalacion-consola.md](instalacion-consola.md) | Instalar el binario sin GUI |
| [instalacion-windows-usuario.md](instalacion-windows-usuario.md) | Instalador gráfico Windows |

Fuera de `docs/`:

- [`README_CONFIG.md`](../README_CONFIG.md) — cada clave de `config_client.json`
- [`README_CLIENT.md`](../README_CLIENT.md) — guía del binario para el usuario final
- [`.env.example`](../.env.example) — variables del servidor
