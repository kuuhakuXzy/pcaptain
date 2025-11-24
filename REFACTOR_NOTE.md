### Docker Compose

- Prod and dev compose files are split (`docker-compose.yml` + `docker-compose.dev.yml`).
- Added health checks for Redis, backend, and frontend.

### Config System

- `.env` is the main place for settings (all `PCAP_` variables work with Dynaconf).
- Config moved to YAML (`config.yaml`) with env overrides.
- `ConfigService` handles dynamic loading, so env vars like `PCAP_BACKEND__BASE_URL` override YAML.

### Service Architecture

- Replaced the old giant `main.py` setup with a simple DI container (`container.py`), using singletons.
- Services split out into their own classes: `ScannerService`, `RedisService`, `PcapParser`, `HashingService`.
- Added a `@service` decorator to auto-register services.

### API Structure

- Broke the old big API file into separate modules:

  - `api/search.py`
  - `api/scan.py`
  - `api/download.py`
  - `api/health.py`
  - `api/errors.py`
