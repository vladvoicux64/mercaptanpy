import socket
import threading
import base64
from scapy.all import DNS, DNSRR, IP, UDP, sr1, RandShort
from collections import defaultdict, deque

TUNNEL_DOMAIN = "tunnel.fancy.pants"
DOMAIN_LABELS = TUNNEL_DOMAIN.split(".")
LISTEN_IP = "0.0.0.0"
DNS_PORT = 53

sessions = {}  # session_id -> TCP socket
buffers = defaultdict(deque)
closed_sessions = set()
session_lock = threading.Lock()
with open("ads-and-tracking-extended.txt", "r") as f:
    blocklist = f.read().split("\n")


def b32pad(s):
    return s + "=" * (-len(s) % 8)


def tcp_connect(sessid, addr, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((addr, port))
        sock.settimeout(None)
        with session_lock:
            sessions[sessid] = sock
        print(f"[+] Connection established for session {sessid} to {addr}:{port}")
        return True
    except Exception as e:
        print(f"[!] TCP connect failed for {sessid}: {e}")
        return False


def handle_dns(packet, addr, raw, sock):
    try:
        if DNS not in packet or not packet.qd:
            return
        q = packet.qd
        qname = q.qname.decode().rstrip(".")
        labels = qname.split(".")

        print(f"[DNS] Query: {qname}")

        if labels[-len(DOMAIN_LABELS) :] == DOMAIN_LABELS:
            cmd = labels[0]
            sessid = labels[1] if len(labels) > 1 else None

            rpacket = DNS(id=packet.id, qr=1, aa=1, qd=q)

            if cmd == "conn":
                encoded = labels[2]
                try:
                    dst = base64.b32decode(b32pad(encoded)).decode()
                    host, port = dst.rsplit(":", 1)
                    port = int(port)
                    result = tcp_connect(sessid, host, port)
                    rdata = "OK" if result else "ERR"
                except Exception as e:
                    print("[!] Error in conn:", e)
                    rdata = "ERR"
                rpacket.an = DNSRR(rrname=q.qname, type="TXT", ttl=10, rdata=rdata)
                sock.sendto(bytes(rpacket), addr)
                return

            elif cmd == "tcp":
                if sessid in closed_sessions:
                    rpacket.an = DNSRR(
                        rrname=q.qname, type="TXT", ttl=10, rdata=f"{labels[2]}:"
                    )
                    sock.sendto(bytes(rpacket), addr)
                    return

                seq = int(labels[2])
                data_labels = labels[3 : -len(DOMAIN_LABELS)]
                incoming_data = (
                    base64.b32decode(b32pad("".join(data_labels)))
                    if data_labels != ["0"]
                    else b""
                )

                seq_key = (sessid, "seq")
                next_seq_key = (sessid, "next_seq")

                if seq_key not in buffers:
                    buffers[seq_key] = deque()
                if next_seq_key not in buffers:
                    buffers[next_seq_key] = 0

                with session_lock:
                    s = sessions.get(sessid)
                if not s:
                    rpacket.an = DNSRR(
                        rrname=q.qname, type="TXT", ttl=10, rdata=f"{seq}:"
                    )
                    sock.sendto(bytes(rpacket), addr)
                    return

                if incoming_data:
                    try:
                        s.sendall(incoming_data)
                    except Exception as e:
                        print(f"[!] Send error on sess {sessid}: {e}")
                        with session_lock:
                            if sessid in sessions:
                                try:
                                    sessions[sessid].close()
                                except:
                                    pass
                                del sessions[sessid]
                        rpacket.an = DNSRR(
                            rrname=q.qname, type="TXT", ttl=10, rdata=f"{seq}:"
                        )
                        sock.sendto(bytes(rpacket), addr)
                        return

                try:
                    s.settimeout(0.05)
                    try:
                        outdata = s.recv(200)
                        if outdata:
                            buffers[seq_key].append((buffers[next_seq_key], outdata))
                            buffers[next_seq_key] += 1
                    except socket.timeout:
                        pass

                    if buffers[seq_key]:
                        next_seq, pending_data = buffers[seq_key][0]
                        if next_seq == seq:
                            outdata = buffers[seq_key].popleft()[1]
                        else:
                            outdata = b""
                    else:
                        outdata = b""

                    encoded = (
                        base64.b32encode(outdata).decode().strip("=") if outdata else ""
                    )
                    rdata = f"{seq}:{encoded}"

                except Exception as e:
                    print(f"[!] Recv error on sess {sessid}: {e}")
                    with session_lock:
                        if sessid in sessions:
                            try:
                                sessions[sessid].close()
                            except:
                                pass
                            del sessions[sessid]
                    rdata = f"{seq}:"

                rpacket.an = DNSRR(rrname=q.qname, type="TXT", ttl=10, rdata=rdata)
                sock.sendto(bytes(rpacket), addr)
                return

            elif cmd == "end":
                closed_sessions.add(sessid)
                try:
                    s = sessions.pop(sessid)
                    s.shutdown(socket.SHUT_RDWR)
                    s.close()
                    buffers.pop((sessid, "seq"), None)
                    buffers.pop((sessid, "next_seq"), None)
                except:
                    pass
                rpacket.an = DNSRR(rrname=q.qname, type="TXT", ttl=10, rdata="BYE")
                sock.sendto(bytes(rpacket), addr)
                return

        else:
            domain = qname
            if domain not in blocklist:
                q.qtype = "A"
                dns_req = (
                    IP(dst="9.9.9.9")
                    / UDP(sport=RandShort(), dport=53)
                    / DNS(rd=1, qd=q)
                )
                print("[DNS] Forwarding to external DNS server")

                dns_response = sr1(dns_req, verbose=0, timeout=2)
                if dns_response and dns_response.haslayer(DNS) and dns_response[DNS].an:
                    rpacket = DNS(
                        id=packet.id, qr=1, aa=1, qd=q, an=dns_response[DNS].an
                    )
                else:
                    print("[DNS] No valid DNS response received")
                    return
            else:
                print("[DNS] Blocked:", domain)
                rpacket = DNS(
                    id=packet.id,
                    qr=1,
                    aa=1,
                    qd=q,
                    an=DNSRR(
                        rrname=q.qname, ttl=330, type="A", rclass="IN", rdata="0.0.0.0"
                    ),
                )

            sock.sendto(bytes(rpacket), addr)
            return

    except Exception as e:
        print(f"[!] Error handling DNS: {e}")


def main():
    print(f"[TUNNEL] DNS tunnel server started on {LISTEN_IP}:{DNS_PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((LISTEN_IP, DNS_PORT))
    while True:
        try:
            data, addr = s.recvfrom(512)
            packet = DNS(data)
            threading.Thread(
                target=handle_dns, args=(packet, addr, data, s), daemon=True
            ).start()
        except Exception as e:
            print(f"[!] Packet processing error: {e}")


if __name__ == "__main__":
    main()
