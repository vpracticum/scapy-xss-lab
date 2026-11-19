import argparse
import gzip
import zlib

from scapy.all import sniff, bind_layers, TCP, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.sessions import TCPSession


def bind_http_port(port: int):
    bind_layers(TCP, HTTP, dport=port)
    bind_layers(TCP, HTTP, sport=port)


def to_str(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def dict_headers(headers):
    if not headers:
        return {}
    try:
        return {to_str(k): to_str(v) for k, v in dict(headers).items()}
    except Exception:
        return {}


def extract_headers(layer):
    headers = {}

    # Известные поля Scapy HTTP превращаем в заголовки
    for key, value in getattr(layer, "fields", {}).items():
        if value is None:
            continue

        if key in {
            "Method",
            "Path",
            "Http_Version",
            "Status_Code",
            "Reason_Phrase",
            "Headers",
            "Unknown_Headers",
        }:
            continue

        headers[key.replace("_", "-")] = to_str(value)

    extra = getattr(layer, "Headers", None)
    if extra:
        headers.update(dict_headers(extra))

    return headers


def get_body(pkt):
    if pkt.haslayer(Raw):
        return bytes(pkt[Raw])

    if pkt.haslayer(HTTP):
        payload = pkt[HTTP].payload
        if payload:
            return bytes(payload)

    return b""


def decode_body(headers, body):
    if not body:
        return b""

    encoding = headers.get("Content-Encoding", "").lower()

    if "gzip" in encoding:
        try:
            return gzip.decompress(body)
        except Exception:
            pass

    if "deflate" in encoding:
        try:
            return zlib.decompress(body)
        except Exception:
            pass

        try:
            return zlib.decompress(body, -zlib.MAX_WBITS)
        except Exception:
            pass

    return body


def print_body(body, limit):
    text = body.decode("utf-8", errors="replace")

    if len(text) > limit:
        print(text[:limit])
        print(f"... [обрезано {len(text) - limit} символов]")
    else:
        print(text)


def main():
    ap = argparse.ArgumentParser(description="Analyze pcap with HTTP requests/responses")
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, default=8008)
    ap.add_argument("--max-body", type=int, default=2000)
    args = ap.parse_args()

    bind_http_port(args.port)

    pkts = sniff(offline=args.pcap, session=TCPSession)

    req_count = 0
    resp_count = 0

    for pkt in pkts:
        if pkt.haslayer(HTTPRequest):
            req_count += 1
            req = pkt[HTTPRequest]
            headers = extract_headers(req)
            body = get_body(pkt)

            print("=" * 80)
            print(f"[HTTP REQUEST #{req_count}]")
            print(f"{to_str(req.Method)} {to_str(req.Path)}")

            for k, v in headers.items():
                print(f"{k}: {v}")

            if body:
                print("\n[REQUEST BODY]")
                print_body(decode_body(headers, body), args.max_body)

        elif pkt.haslayer(HTTPResponse):
            resp_count += 1
            resp = pkt[HTTPResponse]
            headers = extract_headers(resp)
            body = get_body(pkt)

            print("=" * 80)
            print(f"[HTTP RESPONSE #{resp_count}] status={to_str(resp.Status_Code)} {to_str(resp.Reason_Phrase)}")

            for k, v in headers.items():
                print(f"{k}: {v}")

            if body:
                print("\n[RESPONSE BODY]")
                print_body(decode_body(headers, body), args.max_body)

    print("=" * 80)
    print(f"Requests: {req_count}, Responses: {resp_count}")

    if req_count == 0 and resp_count == 0:
        print("HTTP не найден. Проверь порт, интерфейс, что трафик был на localhost, и что захват шёл с правами.")


if __name__ == "__main__":
    main()