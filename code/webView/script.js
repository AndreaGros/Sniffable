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

packetTotal=document.getElementById("packetTotal")

// tasto di sniffer
startStop = document.getElementById("startStop")
startStop.addEventListener("click", () => {
    socket.send(JSON.stringify({
        action: isSniffing == false ? "start_sniffer" : "stop_sniffer"
    }))
    isSniffing = !isSniffing
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