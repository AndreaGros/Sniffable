// variabili globali
const socket = new WebSocket("ws://127.0.0.1:5000")
let packets = []
let protos = {
    "tcp": 0,
    "udp": 0,
    "arp": 0,
    "dns": 0,
    "icmp": 0
}
let isSniffing = false
let LAN = "0.0.0.0"

const packetTotal = document.getElementById("packetTotal")
const devicesNumber = document.getElementById("devicesNumber")
const packetBody = document.getElementById("packetBody")
const openPorts = document.getElementById("openPorts")
const sendPacket = document.getElementById("sendPacket")
const timeout = document.getElementById("timeout")
const interfaceList = document.getElementById("interfaceList")
const filter = document.getElementById("filter")

// tasto di sniffer
const startStop = document.getElementById("startStop")
startStop.addEventListener("click", () => {
    socket.send(JSON.stringify({
        action: isSniffing == false ? "start_sniffer" : "stop_sniffer",
        filter: filter.value
    }))
    isSniffing = !isSniffing
    if (isSniffing == true)
        startStop.innerHTML = '<i class="bi bi-stop-fill me-1"></i>STOP'
    else
        startStop.innerHTML = '<i class="bi bi-caret-right-fill"></i>PLAY'
})

// tasto clear
const clear = document.getElementById("clear")
clear.addEventListener("click", () => {
    socket.send(JSON.stringify({
        action: "clear"
    }))
    protos = {
        "tcp": 0,
        "udp": 0,
        "arp": 0,
        "dns": 0,
        "icmp": 0
    }
    packets = []
    updateProtoBars()
    document.querySelector("tbody").innerHTML = ""
    packetTotal.textContent = "0"
})

//tasto download
const download = document.getElementById("download")
download.addEventListener("click", () => {
    socket.send(JSON.stringify({
        action: "download"
    }))
})


// scan
let targetLAN = document.getElementById("targetLAN")
let scanBtn = document.getElementById("scanBtn")

scanBtn.addEventListener("click", () => {
    socket.send(JSON.stringify({
        action: "get_hosts",
        target: targetLAN.value,
        interface: interfaceList.value,
        timeout: timeout.value
    }))
    console.log(targetLAN.value)
})

// send packet
const chkETH = document.getElementById("chkETH");
const dstMAC = document.getElementById("dstMAC");
const srcMAC = document.getElementById("srcMAC");

const chkIP = document.getElementById("chkIP");
const dstIP = document.getElementById("dstIP");
const ttl = document.getElementById("ttl");
const srcIP = document.getElementById("srcIP");

const proto = document.getElementById("proto");
const dstPort = document.getElementById("dstPort");
const flags = document.getElementById("flags");

const chkPayload = document.getElementById("chkPayload");
const payload = document.getElementById("payload");

sendPacket.addEventListener("click", () => {
    let pkt = buildPacket()
    socket.send(JSON.stringify({
        action: "sender",
        "pkt": pkt
    }))
})

function buildPacket() {

    const packet = {};

    if (chkETH.checked) {
        packet.eth = {
            dst: dstMAC.value.trim(),
            src: srcMAC.value.trim() || "auto"
        };
    }

    if (chkIP.checked) {
        packet.ip = {
            dst: dstIP.value.trim(),
            src: srcIP.value.trim() || "auto",
            ttl: parseInt(ttl.value, 10) || 64
        };
    }
    const selectedProto = proto.value;

    if (selectedProto !== "NONE") {

        packet.transport = {
            protocol: selectedProto
        };

        if (selectedProto === "TCP") {
            packet.transport.dstPort = parseInt(dstPort.value, 10) || 0;
            packet.transport.flags = flags.value.trim().toUpperCase();
        }

        if (selectedProto === "UDP") {
            packet.transport.dstPort = parseInt(dstPort.value, 10) || 0;
        }

        if (selectedProto === "ICMP") {
            packet.transport.type = 8;
            packet.transport.code = 0;
        }
    }

    if (chkPayload.checked) {
        packet.payload = payload.value;
    }

    return packet;
}

// socket
socket.addEventListener("open", () => {
    console.log("Open socket")
})
socket.addEventListener("close", () => {
    console.log("Close socket")
})

socket.onmessage = (event) => {
    const msg = JSON.parse(event.data)
    console.log(msg)
    if (msg.type === "packet") {
        const pck = msg.data
        packets.push(pck)
        Object.keys(protos).forEach(key => {
            const protoPcks = packets.filter(
                p => p.proto.toLowerCase() === key
            )
            protos[key] = (
                protoPcks.length / packets.length
            ) * 100
        })
        updateProtoBars()
        packetTotal.textContent = packets.length
        addPacketRow(msg.data)
    }
    else if (msg.type === "detail") {
        packetBody.innerHTML = ''
        Object.entries(msg.data).forEach(([key, value]) => {
            const div = document.createElement("div");

            const k = document.createElement("span");
            k.className = "modal-key";
            k.textContent = key;

            const v = document.createElement("span");
            v.className = "modal-val";

            // HEX trattato separatamente per stile
            if (key.toLowerCase() === "raw_hex" || key.toLowerCase() === "raw_text") {
                const hex = document.createElement("div");
                hex.className = "modal-hex";
                hex.textContent = value;

                packetBody.appendChild(hex);
                return;
            }

            v.textContent = value;

            div.appendChild(k);
            div.appendChild(v);
            packetBody.appendChild(div);
        });


    }
    else if (msg.type === "devices") {
        renderDevices(msg.data)
        devicesNumber.textContent = msg.data.length
        console.log("device renderizzati")
    }
    else if (msg.type === "ports") {
        openPorts.textContent = ""
        openPorts.textContent = msg.data
    }
    else if (msg.type === "pcap_saved"){
        alert("Saved file: " + msg.data)
    }
}

// functions per effetti grafici
function updateProtoBars() {
    Object.entries(protos).forEach(([proto, value]) => {
        const row = document.querySelector(
            `.proto-bar-row[data-proto="${proto}"]`
        )
        if (!row) return
        const bar = row.querySelector(".proto-fill")
        const pct = row.querySelector(".proto-bar-pct")
        const percentage = value.toFixed(1)
        bar.style.width = `${percentage}%`
        pct.textContent = `${percentage}%`
    })
}

function addPacketRow(packet) {
    console.log(packet)
    const tbody = document.querySelector("tbody")

    const row = document.createElement("tr")

    row.addEventListener("click", () => {
        socket.send(JSON.stringify({
            action: "packet_detail",
            packet_id: packet.index
        }))
    })

    row.setAttribute("data-bs-toggle", "modal")
    row.setAttribute("data-bs-target", "#pktModal")

    // protocollo
    const proto = (packet.proto || "unknown").toLowerCase()

    // orario realtime
    const now = new Date()

    const time =
        now.toLocaleTimeString("it-IT", {
            hour12: false
        }) +
        "." +
        String(now.getMilliseconds()).padStart(3, "0")

    row.innerHTML = `
        <td class="text-g1">
            ${packet.index || "-"}
        </td>

        <td class="text-g1">
            ${time}
        </td>

        <td style="color:var(--g3)">
            ${packet.src || "-"}
        </td>

        <td>
            ${packet.dst || "-"}
        </td>

        <td>
            <span class="proto proto-${proto}">
                ${(packet.proto || "UNK").toUpperCase()}
            </span>
        </td>

        <td class="text-g1">
            ${packet.length || "-"}
        </td>
    `
    tbody.appendChild(row)
}

function renderDevices(devices) {

    const container = document.querySelector("#page-devices")

    // rimuove solo i device vecchi
    container.querySelectorAll(".dev-item").forEach(el => el.remove())

    devices.forEach(dev => {

        const el = document.createElement("div")
        el.className = "dev-item"

        el.setAttribute("data-bs-toggle", "modal")
        el.setAttribute("data-bs-target", "#devModal")

        el.innerHTML = `
            <div class="dev-dot"
                 style="background:var(--g3);box-shadow:0 0 5px var(--g3)">
            </div>

            <div class="flex-grow-1">
                <div style="color:var(--g3);">
                    ${dev.ip}
                </div>
                <div style="color:var(--dim);margin-top:2px">
                    ${dev.mac}
                </div>
            </div>

            <div class="text-end">
                <div style="color:var(--g2);font-size:12px">
                    ●
                </div>
                <div style="color:var(--g3);letter-spacing:1px">
                    ONLINE
                </div>
            </div>
        `
        el.addEventListener("click", () => {
            socket.send(JSON.stringify({
                action: "port_scan",
                target: dev.ip,
                startPort: 22,
                endPort: 443
            }))
        })
        container.appendChild(el)
    })
}