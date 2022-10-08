import struct


def align_up(value: int, align: int) -> int:
    return align_down(value + (align - 1), align)


def align_down(value: int, align: int) -> int:
    return value & -align


def is_aligned(value: int, align: int) -> bool:
    return (value & (align - 1)) == 0


def get_alignment(size: int) -> int:
    return size & -size


def get_padding(offset: int, align: int) -> int:
    return -offset & (align - 1)


def pad_format(format_string: str) -> str:
    stripped_endian = ""

    if format_string.startswith(("@", "=", "<", ">", "!")):
        stripped_endian = format_string[0]
        format_string = format_string[1:]

    largest = max(struct.calcsize(c) for c in format_string)

    aligned_format = ""
    offset = 0
    for format_char in format_string:
        align = struct.calcsize(format_char)

        padding = get_padding(offset, align)
        offset += align + padding
        aligned_format += ("x" * padding) + format_char

    aligned_format += "x" * get_padding(offset, largest)

    return stripped_endian + aligned_format
