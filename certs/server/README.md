# Certificados del server (`certs/server/`)

Secretos del backend de control. **No commitear** `.key` ni `.crt` reales (`.gitignore`).

Generar con:

```bash
python scripts/enroll.py --server-only --out-dir ./certs --san tu.host.o.ip
```

O el enroll completo (también crea `certs/server/`):

```bash
python scripts/enroll.py --client-name PC_Linux_Test --out-dir ./certs --san tu.host
```

## Archivos

```
certs/server/
├── README.md       ← esta guía (sí en git)
├── .gitkeep
├── ca.key          ← CA raíz (backup offline; NO en git)
├── ca.crt
├── server.crt      ← TLS :8000 (solo si mTLS en el pod)
├── server.key
└── signing.key     ← firma de comandos (obligatorio en prod)
```

| Archivo | ¿En git? | Robin (ingress TLS) | mTLS en el pod |
|---------|----------|---------------------|----------------|
| `signing.key` | **Nunca** | **Sí, montar** | Sí |
| `server.crt` / `server.key` | **Nunca** | No (sin `SSL_*`) | Sí |
| `ca.crt` / `ca.key` | **Nunca** | No | Sí (ca.crt) |

## Docker / Robin

Los PEM **no van en la imagen**. Montar en runtime.

**Robin** (ingress termina TLS → pod HTTP `:8000`):

```yaml
# Build: ws_client/certs/server/signing.key en contexto Docker (va en imagen).
# Runtime (pod): montar ca.key + ca.crt; NO en imagen.
volumes:
  - ./certs/server/ca.key:/certs/enrollment/ca.key:ro
  - ./certs/server/ca.crt:/certs/enrollment/ca.crt:ro
environment:
  ENROLLMENT_CA_KEY: /certs/enrollment/ca.key
  ENROLLMENT_CA_CERT: /certs/enrollment/ca.crt
```

`SERVER_SIGNING_KEY=/certs/signing.key` viene del Dockerfile.  
No definir `SSL_CERTFILE`, `SSL_KEYFILE`, `SSL_CA_CERTS` ni `SSL_CERT_REQS`.  
Plantilla: `server/.env.robin-ingress`.

**mTLS en el contenedor** (opcional, no Robin):

```yaml
volumes:
  - ./certs/server:/certs/server:ro
environment:
  SSL_CERTFILE: /certs/server/server.crt
  SSL_KEYFILE: /certs/server/server.key
  SSL_CA_CERTS: /certs/server/ca.crt
  SSL_CERT_REQS: required
  SERVER_SIGNING_KEY: /certs/server/signing.key
```

## Permisos

```bash
chmod 600 certs/server/*.key
chmod 644 certs/server/*.crt
```

Sin `signing.key` el server no despacha comandos (fail-closed). Guardar backup en secret manager del cluster.
