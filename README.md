# Spring Boot DevSecOps Lab

Aplicacion deliberadamente vulnerable para prácticas controladas de SAST, SCA,
secret scanning, análisis de contenedores y DAST.

> **Advertencia:** ejecutar únicamente en `localhost` o en una red de laboratorio
> aislada. No desplegar en Internet ni reutilizar credenciales reales.

## Requisitos

- JDK 21
- Maven 3.9+
- Docker, opcional
- Semgrep, para el análisis local

## Iniciar la aplicación

```bash
mvn clean verify
mvn spring-boot:run
```

La aplicación estará disponible en `http://localhost:8080`.

## Endpoints del laboratorio

```text
GET  /api/products/search?name=Laptop
POST /api/comments/preview
GET  /api/admin/users/1
POST /api/auth/login
```

Ejemplo para la vista previa:

```bash
curl -X POST http://localhost:8080/api/comments/preview \
  -H "Content-Type: application/json" \
  -d '{"comment":"Comentario de prueba"}'
```

Ejemplo de autenticación:

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"usuario","password":"prueba"}'
```

## Analisis local (SAST + SCA)

```bash
# Semgrep (con Docker)
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep semgrep scan \
  --config auto --config .semgrep.yml \
  --json-output=reports/local/semgrep-results.json src/main/java

# SpotBugs + Find Security Bugs
mvn -B -DskipTests compile com.github.spotbugs:spotbugs-maven-plugin:spotbugs

# OWASP Dependency-Check (requiere API key de NVD en la variable NVD_API_KEY)
export NVD_API_KEY=<tu-api-key>
mvn -B org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=11

# Quality Gate sobre los reportes generados
python3 .github/scripts/quality_gate.py \
  --semgrep reports/local/semgrep-results.json \
  --spotbugs target/spotbugsXml.xml \
  --dependency-check target/dependency-check-report.json
```

## Pipelines (GitHub Actions)

| Workflow | Disparador | Contenido |
|---|---|---|
| `ci.yml` - CI - Feature | push a `feature/**`, `bugfix/**`, `hotfix/**` | Build & Test, Semgrep, SpotBugs, Quality Gate |
| `ci-cd.yml` - CI/CD - main & develop | push y PR a `main`, `develop` | CI + CodeQL + Quality Gate; en push: Docker build, Trivy y push a GHCR |
| `nightly-sca.yml` - CI/CD - Nightly + SCA | cron diario 02:00 (La Paz) y manual | CI + CodeQL + OWASP Dependency-Check + SBOM CycloneDX + Quality Gate |
| `security-pipeline.yml` | `workflow_call` | Workflow reutilizable con todos los jobs |

El **Quality Gate** (`.github/scripts/quality_gate.py`) descarga los reportes de
todas las herramientas y falla si encuentra hallazgos criticos:

- Semgrep: severidad `ERROR`.
- SpotBugs / Find Security Bugs: categoria `SECURITY` con rank <= 12.
- OWASP Dependency-Check: CVSS >= 9.0 (con `QG_FAIL_ON_HIGH=true`, CVSS >= 7.0).
- CodeQL (SARIF): `security-severity` >= 9.0.

Las ramas `main` y `develop` estan protegidas: el check requerido
`CI-CD / Quality Gate` debe pasar para poder hacer merge de un pull request.

El secreto `NVD_API_KEY` debe configurarse en *Settings > Secrets and variables > Actions*.

El docente dispone de `docs/GUIA-DOCENTE.md`, que contiene el catálogo de
hallazgos y las pruebas sugeridas. Se recomienda entregar inicialmente a los
estudiantes el resto del repositorio sin dicho documento.
