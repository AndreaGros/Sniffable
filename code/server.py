import asyncio
import json
from websockets.asyncio.server import serve
from sniffer_logic import Sniffer
from port_scanner_logic import Scanner
from packet_sender_logic import Sender
from ifaces import get_interfaces

PORT = 5000

packet_queue = asyncio.Queue(maxsize=1000)
sniffer = None


def server_callback(data, loop):
    def safe_put():
        try:
            packet_queue.put_nowait(data)
        except asyncio.QueueFull:
            pass
    loop.call_soon_threadsafe(safe_put)


async def packet_stream(websocket):
    while True:
        packet = await packet_queue.get()

        await websocket.send(json.dumps({"type": "packet", "data": packet}))


def packet_from_json(data: dict, iface=None):

    sender = Sender(iface=iface)
    eth = data.get("eth")

    if eth:
        sender.add_ether(dst=eth.get("dst", "ff:ff:ff:ff:ff:ff"), src=eth.get("src", "192.168.1.1"))

    ip = data.get("ip")

    if ip:
        sender.add_ip(
            dst=ip.get("dst", "127.0.0.1"), src=ip.get("src"), ttl=ip.get("ttl", 64)
        )

    transport = data.get("transport")

    if transport:

        proto = transport.get("protocol", "").upper()

        if proto == "TCP":
            sender.add_tcp(
                dport=transport.get("dstPort", 80),
                sport=transport.get("srcPort"),
                flags=transport.get("flags", "S"),
                seq=transport.get("seq"),
            )

        elif proto == "UDP":
            sender.add_udp(
                dport=transport.get("dstPort", 80), sport=transport.get("srcPort")
            )

        elif proto == "ICMP":
            sender.add_icmp()

    payload = data.get("payload")

    if payload:
        sender.add_payload(payload)

    return sender

async def handle_get_interfaces(websocket, data):
    interfaces = get_interfaces()
    print(interfaces)
    await websocket.send(json.dumps({"type": "interfaces", "data": interfaces}))

async def handle_start_sniffer(websocket, data):
    try:
        sniffer.start(data.get("filter"), data.get("iface"))
        await websocket.send(json.dumps({"type": "status", "data": "sniffer_started"}))
    except ValueError as e:
        await websocket.send(json.dumps({"type": "error", "data": str(e)}))


async def handle_stop_sniffer(websocket, data):
    sniffer.stop()
    await websocket.send(json.dumps({"type": "status", "data": "sniffer_stopped"}))


async def handle_clear_packets(websocket, data):
    sniffer.packets = {}
    sniffer.index = 0
    print(sniffer.index)

    await websocket.send(json.dumps({"type": "status", "data": "cleared"}))


async def handle_packet_detail(websocket, data):
    pkt = sniffer.selectSinglePacket(data.get("packet_id"))

    await websocket.send(json.dumps({"type": "detail", "data": pkt}))


async def handle_get_hosts(websocket, data):
    await websocket.send(json.dumps({"type": "status", "data": "scan_started"}))

    loop = asyncio.get_running_loop()
    devices = await loop.run_in_executor(
        None,
        scanner.device_scan,
        data.get("target"),
        float(data.get("timeout")),
        data.get("interface"),
    )

    await websocket.send(json.dumps({"type": "devices", "data": devices}))


async def handle_port_scan(websocket, data):
    target = data.get("target")
    start_port = int(data.get("startPort"))
    end_port = int(data.get("endPort"))

    loop = asyncio.get_running_loop()

    ports = await loop.run_in_executor(
        None, scanner.port_scan, target, start_port, end_port
    )

    await websocket.send(json.dumps({"type": "ports", "data": ports}))


async def handle_sender(websocket, data):
    pkt_structure = data.get("pkt")

    sender_obj = packet_from_json(pkt_structure)

    pkt = sender_obj.build_packet()

    if pkt:
        sender_obj.send(pkt)

async def handle_export_pcap(websocket, data):
    file = sniffer.downloadCom(sniffer.packets)
    await websocket.send(json.dumps({"type": "pcap_saved", "data": file}))

handlers = {
    "get_interfaces": handle_get_interfaces,
    "start_sniffer": handle_start_sniffer,
    "stop_sniffer": handle_stop_sniffer,
    "clear_packets": handle_clear_packets,
    "packet_detail": handle_packet_detail,
    "get_hosts": handle_get_hosts,
    "port_scan": handle_port_scan,
    "sender": handle_sender,
    "download": handle_export_pcap
}


async def handler(websocket):
    stream_task = asyncio.create_task(packet_stream(websocket))

    try:
        async for message in websocket:
            data = json.loads(message)
            action = data.get("action")
            handler_func = handlers.get(action)
            if not handler_func:
                await websocket.send(
                    json.dumps({"type": "error", "data": f"Unknown action: {action}"})
                )
                continue
            await handler_func(websocket, data)

    finally:
        stream_task.cancel()
        sniffer.stop()


async def main():
    global sniffer
    global scanner
    global sender

    loop = asyncio.get_running_loop()

    sniffer = Sniffer(on_packet=lambda data: server_callback(data, loop))
    scanner = Scanner()
    sender = Sender()

    print(f"Server avviato su localhost:{PORT}")

    async with serve(handler, "localhost", PORT):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
