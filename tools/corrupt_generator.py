import argparse
import os
import random

def corrupt_magic_number(file_path, output_path):
    """Destroy the Header/Magic number of the pcap file."""
    if not os.path.isfile(file_path):
        print(f"[Error]: File {file_path} does not exist.")
        return

    with open(file_path, 'rb') as f:
        data = f.read()

    if len(data) < 4:
        print("[Error]: File is too small to be a valid pcap file.")
        return
    
    corrupted_data = b"RACC" + data[4:]

    with open(output_path, 'wb') as f:
        f.write(corrupted_data)
    print(f"[Done]: File with corrupted magic number saved to {output_path}")

def truncate_file(file_path, output_path, bytes_to_keeps=100):
    """Truncate the pcap file to a specified number of bytes."""
    if not os.path.exists(file_path):
        print(f"[Error]: File {file_path} does not exist.")
        return
    
    with open(file_path, 'rb') as f:
        data = f.read()

    if len(data) <= bytes_to_keeps:
        print(f"[Warrning]: The file({len(data)} bytes) is too small to truncate.")
        bytes_to_keeps = max(1, len(data) // 2)
        print(f"Process to trucate the file to {bytes_to_keeps} bytes instead. [Warning]: file too small may not be able to corrupt proferly.")

    corrupted_data = data[:bytes_to_keeps]
    with open(output_path, 'wb') as f:
        f.write(corrupted_data)
    print(f"[Done]: Truncated file saved to {output_path}")

def corrupt_packet_length(file_path, output_path):
    """Corrupt the length field of a packet in the pcap file."""
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return

    with open(file_path, 'rb') as f:
        data = bytearray(f.read())

    if len(data) < 40:
        print("File is too small to find packet header structure and corrupt it.")
        return

    data[32:36] = b"\xff\xff\x00\x00"
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"[Done]: Pcap file with Malformed/bad length saved to {output_path}")

def inject_garbage_bytes(file_path, output_path):
    """Inject random garbage bytes into the pcap file."""
    if not os.path.exists(file_path):
        print(f"[Error]: File {file_path} does not exist.")
        return

    with open(file_path, 'rb') as f:
        data = bytearray(f.read())

    if len(data) < 60:
        print("[Error]: file is too small to inject garbage bytes into it.")
        return
    
    start_pos = random.randint(25, min(100, len(data) - 20))
    corrupt_length = 20  # <-- Đã sửa lỗi chính tả ở đây (thêm chữ r)

    for i in range(start_pos, start_pos + corrupt_length):
        data[i] = random.randint(0, 255)

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"[Done]: File with injected garbage bytes saved to {output_path}")

def generate_empty_file(output_path):
    with open(output_path, 'wb') as f:
        f.write(b"")
    print(f"[Done]: Empty pcap file saved to {output_path}")

if __name__ == "__main__":
    DEFAULT_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "corrupted_files")

    parser = argparse.ArgumentParser(description="A tool to corrupt pcap files for fault tolerance testing.")
    parser.add_argument("-i", "--input", help="Path to the input pcap file.")
    parser.add_argument("-o", "--output", required=False, help="Path to save the corrupted pcap file.")
    parser.add_argument("-t", "--type", choices=["magic", "truncate", "length", "garbage", "empty"], required=True, help="Type of corruption to apply.")

    args = parser.parse_args()
    
    if args.type != "empty" and not args.input:
        parser.error(f"[Error] '{args.type}' Requires an input file. Please provide one using -i or --input.")
        
    final_output = args.output
    if not final_output:
        # Scenario A: User does not provide any output path -> Automatically generate a default output path in the default directory with a name based on the corruption type
        os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)
        final_output = os.path.join(DEFAULT_OUTPUT_DIR, f"corrupted_{args.type}.pcap")
    elif not os.path.isabs(final_output) and not ("/" in final_output or "\\" in final_output):
        # Scenario B: User provides a simple filename without any directory (vd: `-o test.pcap`)
        os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)
        final_output = os.path.join(DEFAULT_OUTPUT_DIR, final_output)
    else:
        # Scenario C: User provides a specific path (vd: `-o /path/to/corrupted.pcap`)
        parent_dir = os.path.dirname(final_output)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

    if args.type == "magic":
        corrupt_magic_number(args.input, final_output)
    elif args.type == "truncate":
        truncate_file(args.input, final_output)
    elif args.type == "length":
        corrupt_packet_length(args.input, final_output)
    elif args.type == "garbage":
        inject_garbage_bytes(args.input, final_output)
    elif args.type == "empty":
        generate_empty_file(final_output)