# Pcap Catalog Service

A high-performance, asynchronous web service that scans directories of pcap files, catalogs them in Redis based on detailed protocol analysis, and provides a powerful REST API to search, download, and get autocomplete suggestions for protocols.

This project uses `tshark`'s native statistics engine for fast analysis and Redis for high-speed indexing and searching. It's designed for efficiency and ease of use, packaged with Docker for simple deployment.

## Features

- High-Performance Scanning: Uses `tshark`'s optimized statistics engine (`-z io,phs`) to analyze pcaps much faster than per-packet methods.
- Intelligent Indexing: Scans are incremental; already indexed and unchanged files are skipped.
- Detailed Metadata: Catalogs not just which protocols are present, but also the packet count for every protocol in the file.
- Redis-Powered: All metadata and indexes are stored in Redis for extremely fast lookups.
- Asynchronous & Non-Blocking: Scanning runs in a background thread, so the API remains responsive at all times.
- Fuzzy Search / Autocomplete: Provides an API endpoint to get live suggestions for protocol names as the user types.
- Dockerized: Fully containerized with Docker and Docker Compose for one-command setup and deployment.
- Interactive API Docs: Automatically generates Swagger/OpenAPI documentation for all endpoints.

## Requirements

- Docker
- Docker Compose

The service, including `tshark` and all dependencies, runs inside a Docker container, so you do not need to install anything on your host machine.

## How to Run

1.  **Place PCAPs:** Place your pcap files into the `pcaps` directory. If it doesn't exist, create it:

    ```bash
    mkdir pcaps
    ```

2.  **Configure (Optional):** The service can be configured using a `.env` file in the project root. You can copy the provided example:

    ```bash
    cp .env.example .env
    ```

    You can then edit the `.env` file to change the pcap directories, Redis host, etc.

3.  **Build and Run:** From the project root directory, build and run the service with a single command:
    ```bash
    docker-compose up --build
    ```
4.  The service is now running. The API is available at `http://localhost:8000`.

## Configuration

The service uses a `.env` file and YAML configuration:

- **Environment Variables:** Edit `.env` to set pcap directories and API server URL
- **Advanced Config:** Modify `backend/.config/config.yaml` for Redis settings, logging level, and CORS origins
- **Environment Override:** Use `PCAP_BACKEND__BASE_URL` or `PCAP_PCAP_MOUNTED_DIRECTORY` env vars to override config values

## Health Monitoring

**Check service health using Make:**

```bash
make health    # Check all container health status
make ps        # Show running services
```

**Direct health check:**

```bash
curl http://localhost:8000/health
```

## API Endpoints

An interactive API documentation (Swagger UI) is available at [http://localhost:8000/docs] after you start the service.

You can also use `curl` for testing.

---

### 1. Scanning and Indexing

_(Note: An initial scan runs automatically on the first startup.)_

- **Trigger a full re-scan of all directories:**

  ```bash
  curl -X POST http://localhost:8000/reindex
  ```

- **Check the status of an ongoing scan:**
  ```bash
  curl http://localhost:8000/scan-status | jq
  ```

### 2. Searching and Suggestions

- **Get autocomplete suggestions (fuzzy search):**

  ```bash
  # Example: User types "ht"
  curl "http://localhost:8000/protocols/suggest?q=ht" | jq
  ```

- **Search for pcaps containing a specific protocol (e.g., 'sip'):**
  ```bash
  curl "http://localhost:8000/search?protocol=sip" | jq
  ```

### 3. Downloading a File

- **To download a file, you must use its SHA256 hash from the search results.**

  **Step 1:** Find the hash from the search results (using CLI).
  **Step 2:** Use the hash in the download URL.

  ```bash
  # Example hash found from searching for 'sip'
  FILE_HASH="a1b2c3d4e5f6..."

  curl -o sip_capture_downloaded.pcap http://localhost:8000/pcaps/download/$FILE_HASH
  ```

### 4. Service Health

- **Check if the service is running:**
  ```bash
  curl http://localhost:8000/health
  ```
