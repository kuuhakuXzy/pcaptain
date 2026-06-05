"""List PCAP-containing subfolders under the configured root."""

import asyncio
import os


async def list_pcap_subfolders(
    root_directory: str,
    allowed_extensions: tuple[str, ...],
) -> list[dict]:
    """Return immediate child folder names that contain at least one PCAP file."""

    def _scan() -> list[dict]:
        results: list[dict] = []
        if not os.path.isdir(root_directory):
            return results
        try:
            entries = sorted(os.listdir(root_directory))
        except OSError:
            return results

        for name in entries:
            full = os.path.join(root_directory, name)
            if not os.path.isdir(full):
                continue
            count = 0
            for _root, _dirs, files in os.walk(full):
                for f in files:
                    if f.endswith(allowed_extensions):
                        count += 1
                        if count >= 1:
                            break
                if count:
                    break
            if count:
                results.append({"name": name, "pcap_count_hint": count})
        return results

    return await asyncio.to_thread(_scan)
