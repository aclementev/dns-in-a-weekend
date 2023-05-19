#!/usr/bin/env python3
"""
Quick and dirty implementation of DNS

Based on https://implement-dns.wizardzines.com/index.html by Julia Evans
"""

from __future__ import annotations

import dataclasses
import io
import random
import socket
import struct
from dataclasses import dataclass

# For reproducibility during tests
random.seed(1)

TYPE_A = 1
CLASS_IN = 1


@dataclass
class DNSHeader:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0


@dataclass
class DNSQuestion:
    name: bytes
    type_: int
    class_: int


@dataclass
class DNSRecord:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes


@dataclass
class DNSPacket:
    header: DNSHeader
    questions: list[DNSQuestion]
    answers: list[DNSRecord]
    authorities: list[DNSRecord]
    additionals: list[DNSRecord]


def header_to_bytes(header: DNSHeader) -> bytes:
    fields = dataclasses.astuple(header)
    # There are 6 fields, so 6 'H'
    return struct.pack("!HHHHHH", *fields)


def question_to_bytes(question: DNSQuestion) -> bytes:
    return question.name + struct.pack("!HH", question.type_, question.class_)


def encode_dns_name(domain_name: str) -> bytes:
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"


def build_query(domain_name: str, record_type: int) -> bytes:
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    RECURSION_DESIRED = 1 << 8
    header = DNSHeader(id=id, num_questions=1, flags=RECURSION_DESIRED)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    return header_to_bytes(header) + question_to_bytes(question)


def parse_header(reader: io.IOBase) -> DNSHeader:
    data = reader.read(12)
    assert data is not None, "No data found on header"
    items = struct.unpack("!HHHHHH", data)
    return DNSHeader(*items)


def decode_name_simple(reader: io.IOBase) -> bytes:
    parts = []
    while (length := reader.read(1)[0]) != 0:
        parts.append(reader.read(length))
    return b".".join(parts)


def decode_name(reader: io.IOBase) -> bytes:
    """Decode the domain name from the response, handling DNS compression
    https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
    """
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            # It's compressed
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)


def decode_compressed_name(length: int, reader: io.IOBase) -> bytes:
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result


def parse_question(reader: io.IOBase) -> DNSQuestion:
    name = decode_name_simple(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack("!HH", data)
    return DNSQuestion(name, type_, class_)


def parse_record(reader: io.IOBase) -> DNSRecord:
    name = decode_name(reader)
    # the type, TTL and data length are 10 bytes in total (2 + 2 + 4 + 2)
    data = reader.read(10)
    type_, class_, ttl, data_len = struct.unpack("!HHIH", data)
    data = reader.read(data_len)
    return DNSRecord(name, type_, class_, ttl, data)


def parse_dns_packet(data: bytes) -> DNSPacket:
    reader = io.BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]

    return DNSPacket(header, questions, answers, authorities, additionals)


def ip_to_string(ip: bytes) -> str:
    return ".".join(str(x) for x in ip)


def lookup_domain(domain_name: str) -> str:
    query = build_query(domain_name, TYPE_A)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))
    data, _ = sock.recvfrom(1024)
    response = parse_dns_packet(data)
    return ip_to_string(response.answers[0].data)


def main() -> int:
    print(lookup_domain("www.example.com"))
    print(lookup_domain("www.google.com"))
    print(lookup_domain("www.facebook.com"))
    print(lookup_domain("www.metafilter.com"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
