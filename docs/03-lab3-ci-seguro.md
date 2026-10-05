# Laboratorio 3 - CI Seguro con SAST y SCA

## Flujo de ramas

```text
feature/**  --push-->  CI - Feature (Build, Semgrep, SpotBugs, Quality Gate)
    |
    | pull request
    v
develop / main  --PR-->   CI/CD (CI + CodeQL + Quality Gate)  <- check requerido
                --push--> CI/CD + CD (Docker build, Trivy, push a GHCR)

cron 02:00 --> CI/CD Nightly + SCA (CI + CodeQL + Dependency-Check + SBOM + Quality Gate)
```

## Proteccion de ramas

`main` y `develop` exigen pull request y el check `CI-CD / Quality Gate`.
La regla tambien aplica a administradores (`enforce_admins`), por lo que un
pipeline fallido bloquea el merge.

## Politica del Quality Gate

| Herramienta | Hallazgo critico |
|---|---|
| Semgrep | severidad `ERROR` |
| SpotBugs + Find Security Bugs | categoria `SECURITY`, rank <= 12 |
| OWASP Dependency-Check | CVSS >= 9.0 |
| CodeQL | `security-severity` >= 9.0 |

Umbral: 0 hallazgos criticos (`QG_MAX_CRITICAL`). Si falta un reporte o falla
un job previo, el gate tambien falla.
