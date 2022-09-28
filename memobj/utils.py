import struct


def pad_format(format_string: str) -> str:
    stripped_endian = ""

    if format_string.startswith(("<", ">")):
        stripped_endian = format_string[0]
        format_string = format_string[1:]

    largest = max(struct.calcsize(i) for i in format_string)

    aligned_format = ""
    for format_char in format_string:
        padding = "x" * (largest - struct.calcsize(format_char) - 1)
        aligned_format += format_char + padding

    return stripped_endian + aligned_format
