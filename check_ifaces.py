from scapy.all import get_if_list, get_if_addr

print("Interfaces:")

for name in get_if_list():
    try:
        ip = get_if_addr(name)
    except Exception:
        ip = "?"

    print(f"- {name} | IP: {ip}")

print("\nЕсли ловишь сайт на localhost, обычно нужен интерфейс: 'Npcap Loopback Adapter'")