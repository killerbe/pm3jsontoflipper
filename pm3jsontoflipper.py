#!/usr/bin/env python3
import argparse
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
    args = parse_args()
    try:
        # Преобразуем пути к абсолютному формату (по желанию):
        input_file = os.path.abspath(args.input)
        output_file = os.path.abspath(args.output)

        card = parse_proxmark3_json_file(input_file)
        write_nfc_file(output_file, card)
        print(
            f"Успешно сконвертировано:\n  Input:  {input_file}\n  Output: {output_file}"
        )
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Конвертер JSON-дампа Proxmark3 в NFC-файл Flipper Zero (Mifare Classic)."
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Путь к входному JSON-файлу дампа Proxmark3",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Путь к выходному .nfc-файлу (Flipper Zero)",
    )
    return parser.parse_args()


def parse_proxmark3_json_file(filename):
    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Проверяем ключевые поля
    if data.get("Created") != "proxmark3":
        raise ValueError("JSON-файл должен иметь 'Created'='proxmark3'.")
    file_type = data.get("FileType", "").lower()
    # Если хотим, чтобы поддерживались 'mfcard', 'mfc v2' и т.п.
    if not file_type.startswith("mf"):
        raise ValueError("Поле 'FileType' не похоже на Mifare-дамп (mf*).")

    card_info = data.get("Card", {})
    uid = decode_hex_data(card_info.get("UID", ""))
    atqa = decode_hex_data(card_info.get("ATQA", ""))
    sak = decode_hex_data(card_info.get("SAK", ""))

    blocks_map = data.get("blocks", {})
    # Сортируем ключи '0', '1', '2', ... как целые числа и извлекаем байты
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
        raise ValueError(f"Некорректная HEX-строка: '{hex_str}'")


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
        mf_size = 0  # не самый типичный вариант

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
