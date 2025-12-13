# Questions about Docker Compose Configuration

## 1. Why need to expose redis port in host machine? Just use the docker network.

In the `docker-compose.yml`, the Redis service exposes its port to the host machine:

```yaml
redis:
  ports:
    - "${REDIS_PORT}:${REDIS_INTERNAL_PORT}"
```

However, the backend service connects to Redis using the host and port from environment variables, defaulting to `localhost` and the internal port:

```python
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_INTERNAL_PORT", 6379))
```

Using the Docker network would allow services to communicate without exposing ports externally.

## 2. What if they use different redis server with username and password?

The current Redis connection in `main.py` does not include authentication:

```python
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
```

To support a different Redis server with username and password, the code would need to be updated to include these parameters, such as:

```python
redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    username=os.getenv("REDIS_USERNAME"),
    password=os.getenv("REDIS_PASSWORD"),
    db=0,
    decode_responses=True
)
```

## 3. Does the internal port for container matter? Service will be reached by call host port, therefore internal port may redundant

The `docker-compose.yml` uses environment variables for internal ports and mounted directories:

```yaml
backend:
  ports:
    - "${BE_BASE_PORT}:${BE_INTERNAL_PORT}"

frontend:
  ports:
    - "${FRONTEND_PORT}:${NGINX_PORT}"
```

And in `nginx.conf`:

```nginx
server {
    listen      ${NGINX_PORT};
    ...
}
```

Internal ports allow flexibility in container configuration, even if services are accessed via host ports. However, in production environments, only the host ports matter for external access, making internal ports potentially redundant. Fixed values could simplify setup but reduce configurability.

## 4. Why need BE_BASE_PORT in frontend? Why not use a single BE_PUBLIC_URL?

The frontend configuration in `config.template.js` includes both BASE_URL and BASE_PORT:

```javascript
window.APP_CONFIG = {
  BASE_URL: "${BE_BASE_URL}",
  BASE_PORT: "${BE_BASE_PORT}",
};
```

In `main.py`, the full URL is constructed:

```python
FULL_BASE_URL = None
if BASE_URL:
    if not BASE_URL.startswith("http://") and not BASE_URL.startswith("https://"):
        BASE_URL = f"http://{BASE_URL}"
    if BASE_PORT:
        FULL_BASE_URL = f"{BASE_URL}:{BASE_PORT}"
    else:
        FULL_BASE_URL = BASE_URL
```

Using a single `BE_PUBLIC_URL` environment variable could specify the full backend URL, including protocol, host, and port. This would eliminate the need for conditional logic in `main.py` to construct the full URL and simplify frontend configuration, especially in production environments where `localhost` is not used.

## 5. Why is the environment variable naming confusing for PCAP directories?

In `docker-compose.yml`, the volume mount uses `${PCAP_DIRECTORIES}` as the host path and `${PCAP_MOUNTED_DIRECTORY}` as the container path:

```yaml
volumes:
  - "${PCAP_DIRECTORIES}:${PCAP_MOUNTED_DIRECTORY}:ro"
```

However, in `main.py`, the code reads `PCAP_MOUNTED_DIRECTORY` and splits it by commas to get multiple directories:

```python
PCAP_DIRECTORIES_STR = os.getenv("PCAP_MOUNTED_DIRECTORY", "pcaps")
PCAP_DIRECTORIES = [path.strip() for path in PCAP_DIRECTORIES_STR.split(',')]
```

This naming is ambiguous because `PCAP_DIRECTORIES` suggests multiple directories, but Docker mounts a single host path. The code treats the mounted path as a string containing comma-separated directory paths within the container.

# Task List

## [x] Extend backend to consume a config file (.yaml) for configurations like log level and API port, replacing direct environment variables.

## [x] Add entrypoint to backend Docker image to populate config file from environment variables. (Handled via Dynaconf environment variable merging)

## [x] Create Docker Compose health check scripts for frontend and backend images to provide general health status.

## [x] Update frontend to display the absolute server path of the desired pcap, not the container path. (Backend now returns public paths using pcap_prefix)
