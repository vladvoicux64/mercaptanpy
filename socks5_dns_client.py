import socket
import threading
import base64
import random
import time
from scapy.all import DNS, DNSQR, IP, Raw, UDP, sr1

TUNNEL_DOMAIN = "tunnel.fancy.pants"
SERVER_IP = "debianvladut.local"
SOCKS_PORT = 1080
DNS_PORT = 53
LONG_WAIT = 0.005
SHORT_WAIT = 0.0025


def b32pad(s):
    return s + "=" * (-len(s) % 8)


def split_labels(s, maxlen=63):
    return [s[i : i + maxlen] for i in range(0, len(s), maxlen)]


def dns_txt_query(qname):
    print(f"    [>] Sending DNS TXT query: {qname}")
    pkt = (
        IP(dst=SERVER_IP)
        / UDP(sport=random.randint(2000, 65000), dport=DNS_PORT)
        / DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
    )
    ans = sr1(pkt, verbose=0, timeout=2)
    if ans and UDP in ans and Raw in ans:
        try:
            dns_pkt = DNS(ans[Raw].load)
            if dns_pkt.ancount > 0:
                rlist = []
                ans_rr = dns_pkt.an
                for _ in range(dns_pkt.ancount):
                    if ans_rr.type == 16:
                        rlist.append(ans_rr.rdata)
                    ans_rr = ans_rr.payload

                val = ""
                for rdata in rlist:
                    if isinstance(rdata, list):
                        val += "".join(s.decode() if isinstance(s, bytes) else s for s in rdata)
                    elif isinstance(rdata, bytes):
                        val += rdata.decode()
                    else:
                        val += rdata

                print(f"    [<] DNS TXT reply: {val!r}")
                return val
            else:
                print("    [!] DNS response has no answer records.")
        except Exception as e:
            print(f"    [!] Error dissecting DNS response: {e}")
    else:
        print("    [!] No reply or missing Raw UDP payload to dissect.")
    return None


def relay_up(sock, sessid, stop_event):
    seq = 0
    try:
        while not stop_event.is_set():
            chunk = sock.recv(200)
            if not chunk:
                break
            if stop_event.is_set():
                break
            up_b32 = base64.b32encode(chunk).decode().strip("=")
            labels = (
                ["tcp", sessid, str(seq)]
                + split_labels(up_b32)
                + TUNNEL_DOMAIN.split(".")
            )
            qname = ".".join(labels)
            dns_txt_query(qname)
            seq += 1
            time.sleep(SHORT_WAIT)  # or LONG_WAIT
    except Exception as e:
        print(f"    [!] Relay UP error: {e}")
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        except:
            pass
        stop_event.set()
        print(f"[x] UP link closed for session {sessid}")


def relay_down(sock, sessid, stop_event):
    expected_seq = 0
    buffer = {}
    empty_responses = 0
    retry_count = 0

    try:
        while not stop_event.is_set():
            qname = f"tcp.{sessid}.{expected_seq}.0.{TUNNEL_DOMAIN}"
            txt = dns_txt_query(qname)

            if txt is None:
                retry_count += 1
                if retry_count > 5:
                    break
                time.sleep(LONG_WAIT)
                continue

            if txt == "BYE":
                print(f"    [!] Server sent BYE for session {sessid}")
                stop_event.set()
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                except:
                    pass
                break

            if ":" in txt:
                tseq_str, payload = txt.split(":", 1)
                try:
                    tseq = int(tseq_str)
                except:
                    continue

                if payload:
                    try:
                        data = base64.b32decode(b32pad(payload))
                        if tseq == expected_seq:
                            sock.sendall(data)
                            expected_seq += 1
                            empty_responses = 0
                            retry_count = 0
                            while expected_seq in buffer:
                                sock.sendall(buffer.pop(expected_seq))
                                expected_seq += 1
                        elif tseq > expected_seq and tseq not in buffer:
                            buffer[tseq] = data
                    except Exception as e:
                        print(f"    [!] Error decoding data: {e}")
                        continue
                else:
                    empty_responses += 1
                    if empty_responses > 30:
                        break
                    time.sleep(LONG_WAIT)
            else:
                retry_count += 1
                if retry_count < 3:
                    time.sleep(SHORT_WAIT)
                    continue
                else:
                    retry_count = 0
                    empty_responses += 1
                    if empty_responses > 30:
                        break
                    time.sleep(LONG_WAIT)

    except Exception as e:
        print(f"    [!] Relay DOWN error: {e}")
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        except:
            pass
        stop_event.set()
        print(f"[x] DOWN link closed for session {sessid}")


def socks5_handle(client_sock, client_addr):
    sessid = "%08x" % random.getrandbits(32)
    print(f"[SOCKS] New connection from {client_addr}, session {sessid}")
    stop_event = threading.Event()
    try:
        greeting = client_sock.recv(262)
        client_sock.sendall(b"\x05\x00")
        req = client_sock.recv(4)
        if len(req) < 4 or req[0] != 5 or req[1] != 1:
            raise Exception("Invalid SOCKS5 CONNECT request")
        atyp = req[3]

        if atyp == 1:  # IPv4
            addr_bytes = client_sock.recv(4)
            addr = socket.inet_ntoa(addr_bytes)
        elif atyp == 3:  # Domain name
            domain_len = client_sock.recv(1)[0]
            addr = client_sock.recv(domain_len).decode()
        elif atyp == 4:  # IPv6
            addr_bytes = client_sock.recv(16)
            addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        else:
            raise Exception(f"Unsupported address type: {atyp}")

        port_bytes = client_sock.recv(2)
        port = int.from_bytes(port_bytes, "big")
        dst = f"{addr}:{port}"
        dst_b32 = base64.b32encode(dst.encode()).decode().strip("=")
        qname = f"conn.{sessid}.{dst_b32}.{TUNNEL_DOMAIN}"
        result = dns_txt_query(qname)
        if result != "OK":
            client_sock.sendall(
                b"\x05\x01\x00\x01"
                + socket.inet_aton("0.0.0.0")
                + (9999).to_bytes(2, "big")
            )
            client_sock.close()
            return
        client_sock.sendall(
            b"\x05\x00\x00\x01"
            + socket.inet_aton("0.0.0.0")
            + (9999).to_bytes(2, "big")
        )
        up_thread = threading.Thread(
            target=relay_up, args=(client_sock, sessid, stop_event), daemon=True
        )
        up_thread.start()
        relay_down(client_sock, sessid, stop_event)
        up_thread.join(timeout=1)
        # Send end query here, after relays are done
        dns_txt_query(f"end.{sessid}.{TUNNEL_DOMAIN}")
    except Exception as e:
        print(f"    [!] SOCKS5 error: {e}")
    finally:
        stop_event.set()
        try:
            client_sock.shutdown(socket.SHUT_RDWR)
            client_sock.close()
        except:
            pass


def start_socks5_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", SOCKS_PORT))
    srv.listen(20)
    print(f"[TUNNEL] DNS tunnel client SOCKS5 server running on 127.0.0.1:1080")
    print(f"[TUNNEL] DNS domain: {TUNNEL_DOMAIN}")
    while True:
        c, a = srv.accept()
        threading.Thread(target=socks5_handle, args=(c, a), daemon=True).start()


if __name__ == "__main__":
    start_socks5_server()
