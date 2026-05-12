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

packetTotal = document.getElementById("packetTotal")

// tasto di sniffer
startStop = document.getElementById("startStop")
startStop.addEventListener("click", () => {
    socket.send(JSON.stringify({
        action: isSniffing == false ? "start_sniffer" : "stop_sniffer"
    }))
    isSniffing = !isSniffing
})

// tasto clear
clear = document.getElementById("clear")
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
})

// scan
let targetLAN = document.getElementById("targetLAN")
let scanBtn = document.getElementById("scanBtn")

scanBtn.addEventListener("click", () => {
    socket.send(JSON.stringify({
        action: "get_hosts",
        target: targetLAN.value
    }))
    console.log(targetLAN.value)
})

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
    else if (msg.type === "devices") {
        renderDevices(msg.data)
        console.log("device renderizzati")
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
                <div style="color:var(--g3);font-size:14px">
                    ${dev.ip}
                </div>
                <div style="color:var(--dim);font-size:10px;margin-top:2px">
                    ${dev.mac}
                </div>
            </div>

            <div class="text-end">
                <div style="color:var(--g2);font-size:12px">
                    ●
                </div>
                <div style="font-size:9px;color:var(--g3);letter-spacing:1px">
                    ONLINE
                </div>
            </div>
        `

        container.appendChild(el)
    })
}