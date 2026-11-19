import argparse
import os
import time

from scapy.all import AsyncSniffer, wrpcap, bind_layers, TCP
from scapy.layers.http import HTTP
from scapy.sessions import TCPSession


def bind_http_port(port: int):
    bind_layers(TCP, HTTP, dport=port)
    bind_layers(TCP, HTTP, sport=port)


def main():
    ap = argparse.ArgumentParser(description="Capture HTTP traffic and save pcap")
    ap.add_argument("--port", type=int, default=8008)
    ap.add_argument("--iface", default=None, help="Например: Npcap Loopback Adapter")
    ap.add_argument("--out", default="captures/normal.pcap")
    ap.add_argument("--timeout", type=int, default=120, help="Секунды. 0 - без таймаута.")
    args = ap.parse_args()

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    bind_http_port(args.port)

    print(f"[i] Порт: {args.port}")
    print(f"[i] Интерфейс: {args.iface or 'интерфейс по умолчанию'}")
    print(f"[i] Файл: {args.out}")
    print("[i] Теперь открой браузер и работай с приложением. Остановка: Ctrl+C.")

    sniffer = AsyncSniffer(
        filter=f"tcp port {args.port}",
        iface=args.iface,
        session=TCPSession,
        store=True,
    )

    sniffer.start()
    start = time.time()

    try:
        while sniffer.running:
            time.sleep(0.5)
            if args.timeout > 0 and time.time() - start > args.timeout:
                print("[i] Таймаут достигнут, останавливаю захват.")
                break
    except KeyboardInterrupt:
        print("[i] Ctrl+C, останавливаю захват.")
    finally:
        pkts = sniffer.stop()
        if pkts:
            wrpcap(args.out, pkts)
            print(f"[+] Сохранено {len(pkts)} пакетов в {args.out}")
        else:
            print("[-] Пакетов нет. Проверь: запуск от админа, имя интерфейса, Npcap loopback, порт.")


if __name__ == "__main__":
    main()