#!/usr/bin/env python3
import json
import binascii
import sys
import os


class MifareCard:
    def __init__(self, uid, atqa, sak, blocks):
        self.uid = uid  # bytes
        self.atqa = atqa  # bytes
        self.sak = sak  # bytes
        self.blocks = blocks  # list of bytes for each block


def main():
    try:
        # Request file paths via input
        input_file = input("Enter the path to the Proxmark3 JSON dump file: ").strip()
        output_file = input(
            "Enter the path to the output .nfc file (Flipper Zero): "
        ).strip()

        # Convert paths to absolute format
        input_file = os.path.abspath(input_file)
        output_file = os.path.abspath(output_file)

        # Check if a complete path with filename is specified for the output file
        if os.path.isdir(output_file):
            default_name = "output.nfc"
            output_file = os.path.join(output_file, default_name)
            print(f"Output path was a directory, using: {output_file}")

        # Verify input file exists
        if not os.path.isfile(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")

        card = parse_proxmark3_json_file(input_file)

        # Create directory for output file if it doesn't exist
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        write_nfc_file(output_file, card)
        print(
            f"Successfully converted:\n  Input:  {input_file}\n  Output: {output_file}"
        )
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def parse_proxmark3_json_file(filename):
    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Check key fields
    if data.get("Created") != "proxmark3":
        raise ValueError("JSON file must have 'Created'='proxmark3'.")
    file_type = data.get("FileType", "").lower()
    # Support for 'mfcard', 'mfc v2', etc.
    if not file_type.startswith("mf"):
        raise ValueError(
            "The 'FileType' field doesn't appear to be a Mifare dump (mf*)."
        )

    card_info = data.get("Card", {})
    uid = decode_hex_data(card_info.get("UID", ""))
    atqa = decode_hex_data(card_info.get("ATQA", ""))
    sak = decode_hex_data(card_info.get("SAK", ""))

    blocks_map = data.get("blocks", {})
    # Sort keys '0', '1', '2', ... as integers and extract bytes
    sorted_block_keys = sorted(blocks_map.keys(), key=lambda x: int(x))
    blocks = []
    for k in sorted_block_keys:
        block_hex = blocks_map[k]
        block_bytes = decode_hex_data(block_hex)
        blocks.append(block_bytes)

    return MifareCard(uid, atqa, sak, blocks)


def decode_hex_data(hex_str):
    try:
        return binascii.unhexlify(hex_str)
    except binascii.Error:
        raise ValueError(f"Invalid HEX string: '{hex_str}'")


def write_nfc_file(filename, card):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(generate_nfc_content(card))


def generate_nfc_content(card):
    lines = []
    lines.append("Filetype: Flipper NFC device")
    lines.append("Version: 2")
    lines.append(
        "# Nfc device type can be UID, Mifare Ultralight, Mifare Classic, Bank card"
    )
    lines.append("Device type: Mifare Classic")
    lines.append("# UID, ATQA and SAK are common for all formats")
    lines.append(f"UID: {format_hex_data(card.uid)}")
    lines.append(f"ATQA: {format_hex_data(card.atqa)}")
    lines.append(f"SAK: {format_hex_data(card.sak)}")
    lines.append("# Mifare Classic specific data")

    block_count = len(card.blocks)
    if block_count == 64:
        mf_size = 1
    elif block_count == 128:
        mf_size = 2
    elif block_count == 256:
        mf_size = 4
    else:
        mf_size = 0  # uncommon case

    lines.append(f"Mifare Classic type: {mf_size}K")
    lines.append("Data format version: 2")
    lines.append("# Mifare Classic blocks, '??' means unknown data")

    for i, block_data in enumerate(card.blocks):
        lines.append(f"Block {i}: {format_hex_data(block_data)}")

    return "\n".join(lines) + "\n"


def format_hex_data(bdata):
    return " ".join(f"{byte:02X}" for byte in bdata)


if __name__ == "__main__":
    main()
