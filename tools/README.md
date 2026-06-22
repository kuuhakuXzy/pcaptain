# PCAP Corrupt Generator & Testing Guide

This directory contains a Python utility to generate malformed PCAP files.

---

## The 5 Test Scenarios

| Error Type | Description | Simulation Method |
| :--- | :--- | :--- |
| **`magic`** | Invalid file signature / bad magic number. | Overwrites file start with a random text string. |
| **`truncate`**| Cut short due to premature End-Of-File (EOF). | Truncates a valid PCAP file mid-stream. |
| **`length`** | Packet length field mismatch. | Sets header length descriptors larger than actual payload. |
| **`garbage`** | Corrupted block sequences / raw noise. | Injects random bytes into mid-sections of a valid file. |
| **`empty`** | 0-byte file or header-only with no frames. | Creates a 0-byte file or clips immediately after the 24-byte header. |

---

## Execution Guide

### 1. Run the Generator
Execute the script from your terminal. It relies purely on built-in Python modules (no `pip` installs needed):

```bash
python tools/corrupt_generator.py -i "pcap file directory" -o /path/to/your/pcaps/ -t "Error type"
If -o is omitted, files will default to your local ./tools/corrupted_files/ folder.

2. Output Targets
The script generates 5 test files in your target directory:
corrupted_magic.pcap, corrupted_truncate.pcap, corrupted_length.pcap, corrupted_garbage.pcap, and corrupted_empty.pcap.

Verification Workflow
Trigger Scan: Click Scan -> All on the PCAPTAIN dashboard to poll the folder.

Check Ingestion Logs: Verify the backend container registers the errors:

Plaintext
[ERROR] fastscan exited with error for error_magic.pcap: unknown file format
[WARNING] Processing error (magic) for error_magic.pcap. Indexing file with error state.
Check DB Integrity: Confirm the Redis hash key (pcap:file:<hash>) includes:

"has_error": "true"

"error_type": "magic" (or respective error type)

Confirm Frontend UI: Force-reload your browser (Ctrl + F5 / Cmd + Shift + R). The error_*.pcap entries must display with a light red background row, a red exclamation alert icon, and an empty state under the Matched column.


---

### Main `README.md` Bullet Point (Root Directory)
Add this concise line to your main project documentation:

```markdown
* **Defensive Error Handling:** Catalogs and highlights structurally corrupted PCAP files (magic, truncate, length, garbage, empty) using distinct red-row alert UI states. See `tests/README.md` to run the automated test-harness script.