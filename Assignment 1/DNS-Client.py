import random
import socket
import struct

DNS_PORT = 53
DEFAULT_TIMEOUT = 3.0 


def encode_domain_name(domain: str) -> bytes:
    """Encodes standard domain name 'www.example.com' into DNS QNAME format."""
    encoded = b""
    for part in domain.strip().split("."):
        if part:
            encoded += bytes([len(part)]) + part.encode("utf-8")
    encoded += b"\x00"
    return encoded


def decode_domain_name(data: bytes, offset: int) -> tuple[str, int]:
    """Reads a domain name from binary data starting at offset.

    Handles DNS label compression pointers (0xC0).
    Returns (domain_name_string, next_offset_in_packet).
    """
    labels = []
    jumped = False
    original_offset = offset
    bytes_read = 0

    while True:
        length = data[offset]

        if (length & 0xC0) == 0xC0:
            if not jumped:
                bytes_read += 2
                jumped = True
            pointer_offset = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer_offset
            continue

        if length == 0:
            if not jumped:
                bytes_read += 1
            break

        offset += 1
        labels.append(data[offset : offset + length].decode("utf-8", errors="ignore"))
        offset += length

        if not jumped:
            bytes_read += 1 + length

    final_offset = original_offset + bytes_read if jumped else offset + 1
    return ".".join(labels), final_offset


def build_dns_query(domain: str) -> tuple[bytes, int]:
    """Builds a raw DNS request payload for Type A (IPv4)."""
    transaction_id = random.randint(0, 0xFFFF)
    flags = 0x0100  
    qdcount = 1

    header = struct.pack(
        ">HHHHHH", transaction_id, flags, qdcount, 0, 0, 0
    )
    qname = encode_domain_name(domain)
    question = qname + struct.pack(">HH", 1, 1)

    return header + question, transaction_id


def parse_dns_response(
    response: bytes, expected_tx_id: int
) -> dict | None:
    """Parses raw DNS UDP response bytes into structured record data."""
    if len(response) < 12:
        print("[!] Error: Response too short to contain a valid header.")
        return None

    # Unpack Header
    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        ">HHHHHH", response[:12]
    )

    if tx_id != expected_tx_id:
        print(
            f"[!] Error: Transaction ID mismatch! Expected {hex(expected_tx_id)}, got {hex(tx_id)}"
        )
        return None

    rcode = flags & 0x000F
    rcode_messages = {
        0: "NoError (Success)",
        1: "FormErr (Format Error)",
        2: "ServFail (Server Failure)",
        3: "NXDomain (Non-Existent Domain)",
        4: "NotImp (Not Implemented)",
        5: "Refused (Query Refused)",
    }
    status_str = rcode_messages.get(rcode, f"Unknown Error ({rcode})")

    offset = 12

    q_names = []
    for _ in range(qdcount):
        qname, offset = decode_domain_name(response, offset)
        qtype, qclass = struct.unpack(">HH", response[offset : offset + 4])
        offset += 4
        q_names.append((qname, qtype, qclass))

    answers = []
    if rcode == 0:
        for _ in range(ancount):
            name, offset = decode_domain_name(response, offset)
            rtype, rclass, ttl, rdlength = struct.unpack(
                ">HHIH", response[offset : offset + 10]
            )
            offset += 10
            rdata = response[offset : offset + rdlength]
            offset += rdlength

            if rtype == 1 and rdlength == 4:
                ip_address = socket.inet_ntoa(rdata)
                answers.append(
                    {
                        "name": name,
                        "type": "A",
                        "ttl": ttl,
                        "ip": ip_address,
                    }
                )

    return {
        "tx_id": hex(tx_id),
        "status": status_str,
        "rcode": rcode,
        "questions": q_names,
        "answers": answers,
    }


def query_dns_server(domain: str, server_ip: str):
    """Sends the DNS query over UDP and prints detailed results."""
    query_bytes, tx_id = build_dns_query(domain)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(DEFAULT_TIMEOUT)

    try:
        client_socket.sendto(query_bytes, (server_ip, DNS_PORT))

        response, _ = client_socket.recvfrom(512)
        parsed = parse_dns_response(response, tx_id)

        if not parsed:
            return

        print(f" DNS QUERY RESULTS FOR: {domain}")
        print(f" DNS Server Used:   {server_ip}:{DNS_PORT}")
        print(f" Transaction ID:    {parsed['tx_id']}")
        print(f" Response Status:   {parsed['status']}")

        if parsed["questions"]:
            qname, qtype, _ = parsed["questions"][0]
            type_str = "A" if qtype == 1 else str(qtype)
            print(f" Query Name:        {qname}")
            print(f" Query Type:        {type_str}")

        if parsed["answers"]:
            print(" ANSWER RECORDS:")
            for idx, ans in enumerate(parsed["answers"], 1):
                print(
                    f"  [{idx}] IPv4 Address: {ans['ip']}  |  TTL: {ans['ttl']} seconds"
                )
        else:
            print(" No Answer Records Received.")

    except socket.timeout:
        print(
            f"\n[!] Timeout Error: Server {server_ip} did not respond within {DEFAULT_TIMEOUT} seconds.\n"
        )
    except socket.gaierror:
        print(f"\n[!] Error: Invalid DNS Server IP address format '{server_ip}'.\n")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}\n")
    finally:
        client_socket.close()


def main():
    print("           CUSTOM DNS QUERY UTILITY (UDP)")

    server_ip = input("Enter DNS Server IP [Default: 8.8.8.8]: ").strip()
    if not server_ip:
        server_ip = "8.8.8.8"

    while True:
        domain = input(
            "Enter domain name to lookup (or type 'exit' to quit): "
        ).strip()
        if domain.lower() in ["exit", "quit", "q"]:
            print("Exiting program.")
            break
        if not domain:
            continue

        query_dns_server(domain, server_ip)


if __name__ == "__main__":
    main()