import os
import asyncio
import json
import logging
from decorators import service
from container import container
from services.hashing_service import HashingService
from services.pcap_parser import PcapParser
from services.redis_service import RedisService


@service
class ScannerService:
    def __init__(self):
        self.hashing_service = container.get(HashingService)
        self.pcap_parser = container.get(PcapParser)
        self.redis_service = container.get(RedisService)

    async def scan(self, directory, base_url=None, target_folder=None, exclude=None):
        if exclude is None:
            exclude = []

        seen = set()
        indexed = 0
        autocomplete_key = "pcap:protocols:autocomplete"
        found_matching_folder = False

        if not await asyncio.to_thread(os.path.isdir, directory):
            logging.warning(f"Directory does not exist: {directory}")
            return {"error": f"Directory '{directory}' does not exist"}

        for root, dirs, files in await asyncio.to_thread(os.walk, directory):
            # If target_folder is specified, only scan paths that contain that folder
            if target_folder:
                # Get relative path from base directory
                rel_path = os.path.relpath(root, directory)
                # Check if target_folder is anywhere in the path (supports nested folders)
                if (
                    target_folder not in rel_path.split(os.sep)
                    and rel_path != target_folder
                ):
                    continue
                found_matching_folder = True

            for file in files:
                if file in exclude or not file.endswith((".pcap", ".pcapng", ".cap")):
                    continue

                path = os.path.join(root, file)
                file_hash = await self.hashing_service.sha256(path)

                if file_hash in seen:
                    continue
                seen.add(file_hash)

                parse = await self.pcap_parser.parse_pcap(path)
                if parse is None or not parse:
                    continue

                size = await asyncio.to_thread(os.path.getsize, path)
                pcap_key = f"pcap:file:{file_hash}"

                url = f"{base_url}/pcaps/download/{file_hash}" if base_url else ""

                pipe = self.redis_service.client.pipeline()
                pipe.hset(
                    pcap_key,
                    mapping={
                        "filename": file,
                        "path": path,
                        "size_bytes": size,
                        "protocols": ",".join(parse.keys()),
                        "protocol_counts": json.dumps(parse),
                        "download_url": url,
                    },
                )

                payload = {proto: 0 for proto in parse.keys()}
                pipe.zadd(autocomplete_key, payload)

                for proto in parse.keys():
                    pipe.sadd(f"pcap:index:protocol:{proto.lower()}", file_hash)

                await asyncio.to_thread(pipe.execute)
                indexed += 1

        if target_folder and not found_matching_folder:
            logging.warning(
                f"No folder named '{target_folder}' found under {directory}"
            )
            return {
                "status": "warning",
                "message": f"No folder named '{target_folder}' found.",
                "indexed_files": 0,
            }

        logging.info(f"Indexing successful. Processed {indexed} files.")
        return indexed
