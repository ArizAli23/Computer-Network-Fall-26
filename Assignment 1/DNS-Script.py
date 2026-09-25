import random
import socket
import struct


def encode_domain_name(domain: str) -> bytes:
    """Converts 'www.example.com' into DNS label format: \\x03www\\x07example\\x03com\\x00"""
    encoded = b""
    for part in domain.split("."):
        encoded += bytes([len(part)]) + part.encode("utf-8")
    encoded += b"\x00"  
    return encoded


def build_dns_query(domain: str) -> tuple[bytes, int]:
    """Constructs a raw binary DNS query for an IPv4 (A record) lookup."""
    transaction_id = random.randint(0, 0xFFFF)
    flags = 0x0100  
    qdcount = 1  
    ancount = 0  
    nscount = 0  
    arcount = 0  

    header = struct.pack(
        ">HHHHHH",
        transaction_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount,
    )

    qname = encode_domain_name(domain)
    qtype = 1  
    qclass = 1  

    question = qname + struct.pack(">HH", qtype, qclass)

    return header + question, transaction_id


if __name__ == "__main__":
    test_domain = "www.example.com"
    query_bytes, tx_id = build_dns_query(test_domain)
    print(f"Transaction ID: {hex(tx_id)}")
    print(f"Raw Query Hex: {query_bytes.hex()}")