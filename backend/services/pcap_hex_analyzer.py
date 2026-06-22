import os
import struct

def hex_dump(data, length=64):
    """Generate a Hex dump string similar to VS Code's Hex Editor interface"""
    lines = [f"--- Hex Dump (First {length} bytes) ---"]
    data_to_dump = data[:length]
    for i in range(0, len(data_to_dump), 16):
        chunk = data_to_dump[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_str:<48}  |{ascii_str}|")
    lines.append("-" * 40)
    return "\n".join(lines)

def analyze_corrupted_pcap(filepath):
    log = []
    log.append(f"Analyzing File: {os.path.basename(filepath)}")
    
    if not os.path.exists(filepath):
        log.append("[!] File does not exist.")
        return "\n".join(log)
        
    file_size = os.path.getsize(filepath)
    log.append(f"[*] File Size: {file_size} bytes")
    
    if file_size == 0:
        log.append("[!] Conclusion: EMPTY Error (0-byte file). Nothing to read.")
        return "\n".join(log)
        
    with open(filepath, 'rb') as f:
        raw_data = f.read()

    log.append(hex_dump(raw_data, length=min(64, file_size)))

    if file_size < 4:
        log.append("[!] File is too short, doesn't even contain a Magic Number.")
        return "\n".join(log)

    magic = raw_data[:4]
    magic_hex = magic.hex()
    pcapng_magic = '0a0d0d0a'

    endian = ""
    if magic_hex in ['d4c3b2a1', '4d3cb2a1']:
        endian = "<"
        log.append("[*] Detected: Standard PCAP format (Little-endian).")
    elif magic_hex in ['a1b2c3d4', 'a1b23c4d']:
        endian = ">"
        log.append("[*] Detected: Standard PCAP format (Big-endian).")
    elif magic_hex == pcapng_magic:
        log.append("[*] Detected: PCAPNG format. (Complex block structure).")
        # PCAPNG rất phức tạp, ta trả về log tại đây và đánh dấu lỗi Format/Garbage
        log.append("[!] Conclusion: GARBAGE/FORMAT Error. PCAPNG structures that fail fastscan are generally malformed.")
        return "\n".join(log)
    else:
        log.append(f"[!] Conclusion: MAGIC Error. Invalid Magic Number '{magic_hex}'.")
        log.append("[!] Structure is corrupted from the start, cannot parse Global Header.")
        return "\n".join(log)

    if file_size < 24:
        log.append("[!] Conclusion: TRUNCATE Error. File is truncated, not enough bytes for Global Header.")
        return "\n".join(log)

    try:
        header_format = f"{endian}I H H I I I I"
        global_header = struct.unpack(header_format, raw_data[:24])
        log.append("\n--- Successfully recovered PCAP Global Header ---")
        log.append(f"- Version     : {global_header[1]}.{global_header[2]}")
        log.append(f"- Snap Length : {global_header[5]} bytes (Max length per packet)")
        log.append(f"- Link Type   : {global_header[6]}")
    except Exception as e:
        log.append(f"[!] Cannot recover Global Header due to garbage data: {e}")

    if file_size == 24:
        log.append("\n[!] Conclusion: File contains only the Global Header, no packets found (Empty Error).")
        return "\n".join(log)
        
    if file_size > 24:
        log.append("\n--- Attempting to read the first Packet Header (16 bytes) ---")
        if file_size < 40:
            log.append("[!] Conclusion: TRUNCATE Error. Not enough bytes to contain the first Packet Header.")
            return "\n".join(log)
        try:
            packet_format = f"{endian}I I I I"
            pkt_hdr = struct.unpack(packet_format, raw_data[24:40])
            incl_len, orig_len = pkt_hdr[2], pkt_hdr[3]
            log.append(f"- Timestamp : {pkt_hdr[0]}s {pkt_hdr[1]}µs")
            log.append(f"- Declared Incl Length : {incl_len} bytes")
            log.append(f"- Declared Orig Length : {orig_len} bytes")
            
            actual_available = file_size - 40
            if incl_len > actual_available:
                log.append(f"[!] Conclusion: LENGTH/TRUNCATE Error. Header declares {incl_len} bytes, but only {actual_available} remain.")
            elif incl_len > global_header[5]:
                log.append(f"[!] Conclusion: GARBAGE/LENGTH Error. Packet length ({incl_len}) exceeds SnapLen ({global_header[5]}).")
            else:
                log.append("[*] First Packet Header appears to be structurally valid.")
        except Exception as e:
            log.append(f"[!] Packet Header structure is corrupted (Garbage): {e}")

    return "\n".join(log)