import asyncio
import json
from websockets.asyncio.server import serve
from sniffer_logic import Sniffer
from port_scanner_logic import Scanner
from packet_sender_logic import Sender

PORT = 5000

packet_queue = asyncio.Queue(maxsize=1000)
sniffer = None


def server_callback(data, loop):
    try:
        loop.call_soon_threadsafe(packet_queue.put_nowait, data)
    except asyncio.QueueFull:
        pass  # drop packet se troppo traffico

async def packet_stream(websocket):
    while True:
        packet = await packet_queue.get()

        await websocket.send(json.dumps({"type": "packet", "data": packet}))

def packet_from_json(data: dict, iface=None):

    sender = Sender(iface=iface)
    eth = data.get("eth")

    if eth:
        sender.add_ether(
            dst=eth.get("dst", "ff:ff:ff:ff:ff:ff"),
            src=eth.get("src")
        )

    ip = data.get("ip")

    if ip:
        sender.add_ip(
            dst=ip.get("dst", "127.0.0.1"),
            src=ip.get("src"),
            ttl=ip.get("ttl", 64)
        )

    transport = data.get("transport")

    if transport:

        proto = transport.get("protocol", "").upper()

        if proto == "TCP":
            sender.add_tcp(
                dport=transport.get("dstPort", 80),
                sport=transport.get("srcPort"),
                flags=transport.get("flags", "S"),
                seq=transport.get("seq")
            )

        elif proto == "UDP":
            sender.add_udp(
                dport=transport.get("dstPort", 80),
                sport=transport.get("srcPort")
            )

        elif proto == "ICMP":
            sender.add_icmp()

    payload = data.get("payload")

    if payload:
        sender.add_payload(payload)

    return sender


async def handler(websocket):
    stream_task = asyncio.create_task(packet_stream(websocket))

    try:
        async for message in websocket:
            data = json.loads(message)

            action = data.get("action")

            if action == "start_sniffer":
                sniffer.start()
                await websocket.send(
                    json.dumps({"type": "status", "data": "sniffer_started"})
                )

            elif action == "stop_sniffer":
                sniffer.stop()
                await websocket.send(json.dumps({"type": "status", "data": "sniffer_stopped"}))

            elif action == "clear_packets":
                sniffer.packets = {}
                sniffer.index = 0
                await websocket.send(json.dumps({"type": "status", "data": "cleared"}))

            elif action == "packet_detail":
                pkt = sniffer.selectSinglePacket(data.get("packet_id"))
                print(pkt)
                await websocket.send(json.dumps({"type": "detail", "data": pkt}))

            elif action == "get_hosts":
                await websocket.send(json.dumps({"type": "status", "data": "scan_started"}))
                loop = asyncio.get_running_loop()
                devices = await loop.run_in_executor(
                    None,
                    scanner.device_scan,
                    data.get("target")
                )
                print("target: ", data.get("target"))
                await websocket.send(json.dumps({"type": "devices", "data": devices}))

            elif action == "port_scan":
                target = data.get("target")
                startPort = int(data.get("startPort"))
                endPort = int(data.get("endPort"))
                loop = asyncio.get_running_loop()
                ports = await loop.run_in_executor(
                    None,
                    scanner.port_scan,
                    target,
                    startPort,
                    endPort
                )
                await websocket.send(json.dumps({"type": "ports", "data": ports}))
            
            elif action == "sender":
                pktStructure = data.get("pkt")
                sender_obj = packet_from_json(pktStructure)
                pkt = sender_obj.build_packet()
                if pkt:
                    sender_obj.send(pkt)


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
