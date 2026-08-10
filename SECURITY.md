# Seguridad — protección de secretos

Este repositorio participa del esquema de protección de secretos de la cuenta
**knklinux**. Hay 4 capas: cuanto más abajo, antes se bloquea el secreto.

| Nivel | Mecanismo | Estado |
|-------|-----------|--------|
| 1 · Local | Hook pre-commit con Gitleaks | — sin checkout local configurado |
| 2 · CI | Workflow de Gitleaks (historial completo) | ✅ activo (`.github/workflows/gitleaks.yml`) |
| 3 · Servidor | Secret scanning nativo de GitHub | ✅ activo (repo público) |
| 4 · Config | `.gitleaks.toml` compartido (allowlist de falsos positivos) | ✅ |

> Si clonas este repo para trabajar en él, copia también `hooks/pre-commit` de
> `cybergrad` o `certo-demo` y actívalo con `git config core.hooksPath hooks`
> para tener la capa 1.

## Cómo funciona cada capa

1. **Hook local** — `hooks/pre-commit` (activado con `core.hooksPath=hooks`) ejecuta
   `gitleaks protect --staged` antes de cada `git commit`: si detecta un secreto,
   aborta el commit. Incluye bootstrap automático del binario (release oficial de
   Gitleaks). Salto puntual documentado: `git commit --no-verify` (solo si sabes
   lo que haces).
2. **CI** — el workflow `Gitleaks` ejecuta Gitleaks con `fetch-depth: 0`, que escanea **todo el
   historial** (no solo el último commit): un secreto subido hace tiempo se detecta
   y bloquea el push/PR.
3. **Secret scanning nativo** — en los repos públicos,  GitHub revisa cada push y alerta
   sobre patrones de credenciales conocidos.
4. **Configuración compartida** — `.gitleaks.toml` en la raíz: allowlist de
   ejemplos de documentación, placeholders y credenciales **ficticias de tests**.
   Los falsos positivos nuevos se añaden ahí (con comentario), nunca desactivando
   Gitleaks.

## Si encuentras una fuga

- **No la subas**: pausa, borra la credencial del archivo y usa un secret/var de entorno.
- Si ya está en el historial: revoca la credencial y contacta con el propietario
  de la cuenta para purgar el historial (`filter-branch`/`filter-repo` + force-push).
- Gitleaks también se puede ejecutar a mano: `gitleaks detect --source . --redact`.

## Aviso sobre repos privados

El secret scanning nativo de GitHub en repos **privados** requiere GitHub Advanced
Security (plan de pago); en los públicos es gratis. Donde no está disponible, la
cobertura la dan las capas 1, 2 y 4 (hook + CI + allowlist).
