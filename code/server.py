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
