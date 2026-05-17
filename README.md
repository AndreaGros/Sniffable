# 🐾 Sniffable

> **Network Packet Analyzer & Sender** — WebGUI incapsulata in Electron, backend Python/Scapy, comunicazione real-time via WebSocket.

---

## Indice

1. [Panoramica del Progetto](#1-panoramica-del-progetto)
2. [Architettura](#2-architettura)
3. [Stack Tecnologico](#3-stack-tecnologico)
4. [Installazione e Avvio](#4-installazione-e-avvio)
5. [Interfaccia Utente — Sezioni](#5-interfaccia-utente--sezioni)
   - 5.1 [Capture](#51-capture)
   - 5.2 [Packets](#52-packets)
   - 5.3 [Devices](#53-devices)
   - 5.4 [Sender](#54-sender)
6. [Opzioni di Scan](#6-opzioni-di-scan)
7. [Il Tasto Download](#7-il-tasto-download)
8. [Comunicazione WebSocket](#8-comunicazione-websocket)
9. [Configurazione Hardware](#9-configurazione-hardware)
10. [Note di Sicurezza e Uso Responsabile](#10-note-di-sicurezza-e-uso-responsabile)
11. [Glossario](#11-glossario)
12. [FAQ](#12-faq)

---

## 1. Panoramica del Progetto

**Sniffable** è un'applicazione desktop multi-piattaforma pensata per l'analisi e la manipolazione del traffico di rete. Il nome richiama il concetto di *sniffing*, ossia l'intercettazione passiva dei pacchetti che transitano su un'interfaccia di rete.

Il progetto nasce con l'obiettivo di mettere a disposizione — in un'unica interfaccia moderna e touch-friendly — tutte le funzionalità tipiche degli strumenti di analisi di rete (Wireshark, nmap, hping3), ma con un'esperienza utente notevolmente più accessibile, pensata per girare comodamente anche su hardware compatto come un **Raspberry Pi 5** dotato di schermo touch.

### Obiettivi principali

- **Sniffing passivo** del traffico di rete in tempo reale, con ispezione layer-by-layer dei pacchetti catturati.
- **Scoperta attiva** dei dispositivi connessi sulla LAN tramite scansione ARP, con successivo port scan delle porte più comuni.
- **Packet crafting** e invio di pacchetti personalizzati, configurando manualmente i campi dei layer 2, 3 e 4 del modello OSI.
- **Portabilità**: funziona sia come applicazione desktop autonoma (via Electron) sia come Web App servita localmente, su qualsiasi sistema operativo che supporti Python e Node.js.

### Casi d'uso tipici

| Caso d'uso | Descrizione |
|---|---|
| Analisi del traffico di rete domestico o aziendale | Monitorare quali protocolli e host comunicano sulla rete locale |
| Audit di sicurezza | Verificare quali porte sono esposte dai dispositivi della LAN |
| Didattica e ricerca | Studiare il comportamento dei protocolli di rete a basso livello |
| Troubleshooting | Diagnosticare problemi di connettività analizzando i pacchetti scambiati |
| Test di connettività | Inviare pacchetti personalizzati per verificare il comportamento di firewall e host remoti |

---

## 2. Architettura

Sniffable è composto da **due processi distinti** che comunicano in modo bidirezionale tramite WebSocket:

```
┌────────────────────────────────────────────────────────────────────┐
│                          FRONTEND                                  │
│                  Electron  +  WebGUI (HTML/CSS/JS)                 │
│                                                                    │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────┐  │
│  │  Capture  │  │  Packets  │  │  Devices  │  │    Sender     │  │
│  └───────────┘  └───────────┘  └───────────┘  └───────────────┘  │
└───────────────────────────────┬────────────────────────────────────┘
                                │  WebSocket (ws://)
                                │  full-duplex, bassa latenza
┌───────────────────────────────┴────────────────────────────────────┐
│                           BACKEND                                  │
│                       Python  +  Scapy                             │
│                                                                    │
│  ┌───────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │ Packet Sniffer│  │  LAN Scanner │  │    Packet Sender      │  │
│  │   (Scapy)     │  │  ARP + Ports │  │  (Scapy sendp/send)   │  │
│  └───────────────┘  └──────────────┘  └───────────────────────┘  │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │              WebSocket Server (asyncio / websockets)         │ │
│  └──────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘
                                │
                         Interfaccia di rete
                         (eth0, wlan0, ecc.)
```

### Flusso di una richiesta tipica

1. L'utente preme un pulsante nell'interfaccia (es. **Start** nella sezione Capture).
2. Il frontend costruisce un messaggio JSON e lo invia al server via WebSocket.
3. Il server Python riceve il comando, invoca le API di Scapy e inizia ad operare sulla rete.
4. I risultati (pacchetti, dispositivi, porte aperte) vengono serializzati in JSON e inviati in streaming al frontend.
5. La WebGUI aggiorna l'interfaccia in tempo reale con i dati ricevuti.

### Separazione dei processi

La separazione netta tra frontend e backend offre diversi vantaggi:

- Il backend può girare su un host diverso dal frontend (es. Raspberry Pi come sniffer remoto, browser su PC per la visualizzazione).
- Il frontend è completamente stateless rispetto alle operazioni di rete: non gestisce socket raw né ha bisogno di privilegi elevati.
- È possibile sostituire il frontend con qualsiasi client WebSocket (script, CLI, altro browser) senza modificare il backend.

---

## 3. Stack Tecnologico

### Backend — Python

| Componente | Descrizione |
|---|---|
| **Python ≥ 3.9** | Linguaggio principale del backend |
| **Scapy** | Libreria per sniffing, crafting e invio di pacchetti di rete a basso livello |
| **asyncio** | Gestione asincrona delle connessioni WebSocket e delle operazioni I/O |
| **websockets** | Libreria Python per il server WebSocket |

Scapy è il cuore operativo del backend. Permette di:
- Intercettare pacchetti raw dall'interfaccia di rete (`sniff()`).
- Costruire pacchetti arbitrari strato per strato (`Ether() / IP() / TCP()`).
- Inviare pacchetti a livello 2 (`sendp()`) o livello 3 (`send()`).
- Eseguire scansioni ARP per la scoperta degli host (`arping()`).
- Effettuare port scan tramite costruzione manuale di segmenti TCP SYN.

### Frontend — Electron + WebGUI

| Componente | Descrizione |
|---|---|
| **Electron** | Framework per incapsulare la WebGUI come applicazione desktop nativa |
| **HTML5 / CSS3** | Struttura e stile dell'interfaccia |
| **JavaScript (vanilla o framework)** | Logica di interfaccia e gestione WebSocket lato client |
| **WebSocket API** | Comunicazione real-time con il backend Python |

L'utilizzo di Electron permette a Sniffable di girare come applicazione desktop autonoma senza necessità di un browser esterno, pur mantenendo la flessibilità tipica delle tecnologie web. Su Raspberry Pi con schermo touch, questa caratteristica è particolarmente vantaggiosa: l'interfaccia occupa l'intero schermo e risponde ai gesti touch in modo nativo.

---

## 4. Installazione e Avvio

### Prerequisiti

- Python ≥ 3.9
- pip
- Node.js ≥ 18 (per Electron)
- Privilegi di amministratore / root (necessari per lo sniffing a livello raw)

### Installazione dipendenze Python

```bash
pip install scapy websockets
```

> **Nota:** su alcuni sistemi potrebbe essere necessario installare `libpcap` (Linux/macOS) o `Npcap` (Windows) per consentire a Scapy di accedere all'interfaccia di rete a basso livello.

### Installazione dipendenze Node.js

```bash
npm install
```

### Avvio del backend

```bash
# Con privilegi root (necessario per lo sniffing)
sudo python server.py
```

Il server si mette in ascolto sulla porta WebSocket configurata (default: `ws://localhost:8765`).

### Avvio del frontend Electron

```bash
npm start
```

### Avvio in modalità sviluppo (browser)

Se si vuole utilizzare la WebGUI direttamente nel browser senza Electron:

```bash
# Avviare un server HTTP locale nella cartella del frontend
python -m http.server 3000
# Poi aprire http://localhost:3000 nel browser
```

> Assicurarsi che il backend Python sia già in esecuzione prima di aprire il frontend.

### Avvio su Raspberry Pi

```bash
# Avviare il backend con privilegi elevati
sudo python server.py &

# Avviare Electron in modalità kiosk (schermo intero, touch-friendly)
npm start -- --kiosk
```

---

## 5. Interfaccia Utente — Sezioni

L'interfaccia di Sniffable è suddivisa in quattro sezioni principali, accessibili tramite una barra di navigazione laterale o superiore. Ogni sezione è autonoma e corrisponde a una macro-funzionalità dell'applicazione.

---

### 5.1 Capture

La sezione **Capture** è il pannello di controllo principale per lo sniffing del traffico di rete. Da qui si gestisce l'intero ciclo di vita della cattura dei pacchetti.

#### Pulsanti principali

| Pulsante | Funzione |
|---|---|
| **Start** | Avvia lo sniffer sul backend Python. Il backend inizia a catturare tutti i pacchetti che transitano sull'interfaccia di rete selezionata e li invia in streaming al frontend via WebSocket. |
| **Stop** | Ferma la cattura. I pacchetti già ricevuti rimangono visibili nella sezione Packets. |
| **Clear** | Svuota la lista dei pacchetti visualizzati nell'interfaccia. Non interrompe la cattura in corso: se lo sniffer è attivo, continuerà a catturare e i nuovi pacchetti verranno aggiunti alla lista ora vuota. |

#### Comportamento dello Start/Stop

Quando si preme **Start**, il frontend invia al backend un messaggio WebSocket del tipo:

```json
{
  "action": "start_sniff",
  "interface": "eth0",
  "timeout": 0
}
```

Il backend risponde avviando `scapy.sniff()` in un thread separato e, per ogni pacchetto catturato, invia un evento WebSocket al frontend con la rappresentazione JSON del pacchetto:

```json
{
  "event": "packet",
  "data": {
    "timestamp": "2025-01-15T10:32:01.123Z",
    "src": "192.168.1.10",
    "dst": "8.8.8.8",
    "protocol": "DNS",
    "length": 74,
    "layers": { ... }
  }
}
```

Quando si preme **Stop**, viene inviato un comando di interruzione che ferma il thread di sniffing sul backend.

#### Indicatore di stato

Durante la cattura, l'interfaccia mostra un indicatore visivo (es. pallino verde animato o contatore di pacchetti) per segnalare che lo sniffer è attivo. Questo indicatore cambia stato quando si preme Stop o quando la connessione WebSocket viene interrotta.

---

### 5.2 Packets

La sezione **Packets** è la vista principale per l'analisi dei pacchetti catturati. Mostra in tempo reale tutti i pacchetti ricevuti durante la sessione di cattura corrente.

#### Lista pacchetti

Ogni riga nella lista rappresenta un singolo pacchetto e mostra, a colpo d'occhio, le informazioni più rilevanti:

| Campo | Descrizione |
|---|---|
| **#** | Numero progressivo del pacchetto nella sessione corrente |
| **Timestamp** | Data e ora di cattura con precisione al millisecondo |
| **Sorgente** | Indirizzo IP (o MAC per pacchetti non-IP) sorgente |
| **Destinazione** | Indirizzo IP (o MAC) di destinazione |
| **Protocollo** | Protocollo di livello più alto rilevato (TCP, UDP, DNS, HTTP, ARP, ICMP, ecc.) |
| **Lunghezza** | Dimensione del pacchetto in byte |

La lista si aggiorna automaticamente in tempo reale man mano che il backend invia nuovi pacchetti via WebSocket. Lo scroll automatico può essere bloccato per permettere all'utente di esaminare i pacchetti precedenti.

#### Vista di dettaglio

Cliccando su un pacchetto nella lista, si apre la sua **vista di dettaglio**. Questa vista mostra la struttura completa del pacchetto, layer per layer, esattamente come Scapy la analizza:

```
▼ Ethernet (Layer 2)
    src:  aa:bb:cc:dd:ee:ff
    dst:  11:22:33:44:55:66
    type: 0x0800 (IPv4)

▼ IP (Layer 3)
    version:  4
    ihl:      5
    tos:      0x00
    len:      60
    id:       0x1234
    flags:    DF
    frag:     0
    ttl:      64
    proto:    TCP (6)
    chksum:   0xabcd
    src:      192.168.1.10
    dst:      93.184.216.34

▼ TCP (Layer 4)
    sport:    54321
    dport:    443
    seq:      1234567890
    ack:      0
    dataofs:  10
    reserved: 0
    flags:    S  (SYN)
    window:   65535
    chksum:   0x1234
    urgptr:   0
    options:  [MSS=1460, SAckOK, Timestamp, NOP, WScale=7]

▼ Raw Payload
    (vuoto)
```

I layer vengono visualizzati in modo espandibile/collassabile per facilitare la navigazione anche su pacchetti con molti livelli di incapsulamento.

#### Filtraggio (se disponibile)

Se l'interfaccia implementa un sistema di filtri, è possibile filtrare i pacchetti visualizzati per protocollo, indirizzo sorgente/destinazione o porta, senza interrompere la cattura in corso.

---

### 5.3 Devices

La sezione **Devices** è lo strumento di network discovery: permette di scoprire tutti i dispositivi attivi sulla rete locale e di verificare quali porte TCP sono in ascolto su ciascuno di essi.

#### Inserimento della rete target

Prima di poter eseguire una scansione, è necessario specificare la rete da analizzare. Tramite il **pulsante con icona a rotella/ingranaggio**, si apre un pannello di configurazione dove inserire:

| Campo | Descrizione | Esempio |
|---|---|---|
| **Rete target** | Indirizzo di rete in notazione CIDR | `192.168.1.0/24` |
| **Subnet mask** | Maschera di sottorete (alternativa al CIDR) | `255.255.255.0` |
| **Interfaccia** | Interfaccia di rete da cui inviare i pacchetti ARP | `eth0`, `wlan0` |
| **Timeout scan** | Tempo massimo di attesa per le risposte ARP (secondi) | `2` |

> La notazione CIDR è il metodo preferito. `/24` corrisponde a 254 host (da .1 a .254), `/16` a circa 65.000 host.

#### Scan LAN

Premendo il pulsante **Scan LAN**, il frontend invia al backend il comando di effettuare una scansione ARP dell'intera rete specificata:

```json
{
  "action": "scan_lan",
  "network": "192.168.1.0/24",
  "interface": "eth0",
  "timeout": 2
}
```

Il backend utilizza `scapy.arping()` (o una costruzione manuale equivalente con `Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)`) per inviare richieste ARP broadcast a tutti gli indirizzi dell'intervallo e raccoglie le risposte.

I dispositivi che rispondono vengono elencati nell'interfaccia con:

| Campo | Descrizione |
|---|---|
| **IP** | Indirizzo IPv4 del dispositivo |
| **MAC** | Indirizzo MAC dell'interfaccia di rete |
| **Vendor** | Produttore dell'interfaccia (derivato dal prefisso OUI del MAC, se disponibile) |
| **Hostname** | Nome host risolto tramite DNS inverso (se disponibile) |

#### Port scan per dispositivo

Cliccando su un dispositivo nella lista, Sniffable avvia automaticamente una **scansione delle porte comuni** su quell'host. La scansione viene delegata al backend Python che, tramite Scapy, costruisce e invia pacchetti TCP SYN alle porte target e analizza le risposte.

Le **porte comuni scansionate** includono tipicamente:

| Porta | Servizio |
|---|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443 | HTTPS |
| 445 | SMB |
| 3306 | MySQL |
| 3389 | RDP (Remote Desktop) |
| 5900 | VNC |
| 8080 | HTTP alternativo |
| 8443 | HTTPS alternativo |

> Le porte da scansionare possono essere personalizzate tramite le opzioni di scan (vedi sezione 6).

Il frontend rimane in attesa della risposta WebSocket dal backend. Man mano che le porte vengono analizzate, i risultati vengono inviati in streaming:

```json
{
  "event": "port_result",
  "host": "192.168.1.5",
  "port": 22,
  "state": "open",
  "service": "SSH"
}
```

Le porte risultate **aperte** vengono visualizzate in verde; le porte **chiuse** o **filtrate** possono essere nascoste per chiarezza.

---

### 5.4 Sender

La sezione **Sender** è lo strumento di **packet crafting**: permette di costruire pacchetti completamente personalizzati specificando i valori dei campi di ciascun layer del modello OSI, e di inviarli sulla rete.

Questa funzionalità è la più avanzata dell'applicazione e richiede una conoscenza di base dei protocolli di rete.

#### Layer 2 — Data Link (Ethernet)

| Campo | Descrizione | Esempio |
|---|---|---|
| **src** | MAC address sorgente | `aa:bb:cc:dd:ee:ff` |
| **dst** | MAC address destinazione | `ff:ff:ff:ff:ff:ff` (broadcast) |
| **type** | EtherType (protocollo incapsulato) | `0x0800` (IPv4), `0x0806` (ARP) |

#### Layer 3 — Network (IP)

| Campo | Descrizione | Esempio |
|---|---|---|
| **src** | Indirizzo IP sorgente | `192.168.1.100` |
| **dst** | Indirizzo IP destinazione | `8.8.8.8` |
| **ttl** | Time To Live | `64` |
| **proto** | Protocollo di livello 4 | `6` (TCP), `17` (UDP), `1` (ICMP) |
| **flags** | Flag IP | `DF` (Don't Fragment) |
| **id** | Identificativo del datagramma | `0x1234` |

#### Layer 4 — Transport (TCP/UDP)

**TCP:**

| Campo | Descrizione | Esempio |
|---|---|---|
| **sport** | Porta sorgente | `12345` |
| **dport** | Porta destinazione | `80` |
| **seq** | Numero di sequenza | `0` |
| **ack** | Numero di acknowledgment | `0` |
| **flags** | Flag TCP | `S` (SYN), `A` (ACK), `FA` (FIN+ACK), `R` (RST) |
| **window** | Dimensione della finestra | `65535` |

**UDP:**

| Campo | Descrizione | Esempio |
|---|---|---|
| **sport** | Porta sorgente | `12345` |
| **dport** | Porta destinazione | `53` |
| **len** | Lunghezza del segmento | calcolata automaticamente |

#### Payload

È possibile aggiungere un payload raw (dati grezzi) al pacchetto, specificato come stringa di testo o come sequenza esadecimale.

#### Invio del pacchetto

Il pulsante **"Invia Pacchetto"** trasmette la configurazione al backend:

```json
{
  "action": "send_packet",
  "layers": {
    "ethernet": { "src": "aa:bb:cc:dd:ee:ff", "dst": "11:22:33:44:55:66", "type": "0x0800" },
    "ip":       { "src": "192.168.1.100", "dst": "8.8.8.8", "ttl": 64, "proto": 6 },
    "tcp":      { "sport": 12345, "dport": 80, "flags": "S" },
    "payload":  ""
  }
}
```

Il backend ricostruisce il pacchetto con Scapy e lo invia:

```python
packet = Ether(src=..., dst=...) / IP(src=..., dst=..., ttl=...) / TCP(sport=..., dport=..., flags=...)
sendp(packet, iface="eth0")
```

Il risultato dell'invio (successo o errore) viene notificato al frontend via WebSocket.

#### Casi d'uso del Sender

- **Test di firewall**: inviare un pacchetto TCP SYN a una porta specifica per verificare se è raggiungibile.
- **Simulazione di traffico**: generare pacchetti con IP sorgente arbitrario per testare il comportamento di IDS/IPS.
- **Studio dei protocolli**: costruire manualmente un handshake TCP o una richiesta DNS per capirne il funzionamento.
- **Test di connettività a basso livello**: inviare ping ICMP personalizzati o pacchetti ARP gratuitous.

---

## 6. Opzioni di Scan

Le opzioni di scan sono accessibili tramite il pannello di configurazione (pulsante rotella) nella sezione Devices. Permettono di personalizzare il comportamento sia della scansione LAN che del port scan per adattarlo alle esigenze specifiche e alle caratteristiche della rete analizzata.

### Opzioni generali

#### Interfaccia di rete (`interface`)

Permette di scegliere quale interfaccia di rete utilizzare per le operazioni di scanning e sniffing.

| Valore tipico | Descrizione |
|---|---|
| `eth0` | Prima interfaccia Ethernet cablata |
| `eth1` | Seconda interfaccia Ethernet (es. su Raspberry Pi con adattatore USB) |
| `wlan0` | Interfaccia Wi-Fi principale |
| `wlan1` | Seconda interfaccia Wi-Fi |
| `lo` | Loopback (solo per test locali) |

L'elenco delle interfacce disponibili viene popolato dinamicamente dal backend, che interroga il sistema operativo al momento della connessione WebSocket. Questo garantisce che vengano mostrate solo le interfacce effettivamente presenti e attive sul dispositivo.

> Su Raspberry Pi con schermo touch, l'interfaccia predefinita è tipicamente `eth0` se il Raspberry è collegato via cavo, oppure `wlan0` se usa il Wi-Fi.

#### Timeout di scan (`timeout`)

Definisce il tempo massimo (in secondi) che il backend aspetta le risposte prima di considerare conclusa la scansione.

| Fase | Effetto del timeout |
|---|---|
| **Scan LAN (ARP)** | Tempo di attesa per le risposte ARP dai dispositivi della rete. Un valore basso (1-2 s) è sufficiente su reti locali veloci; su reti lente o con molti host potrebbe essere necessario aumentarlo. |
| **Port scan** | Tempo massimo di attesa per la risposta TCP di ciascuna porta. Porte filtrate da firewall non rispondono mai: un timeout basso riduce i tempi ma può generare falsi negativi. |

**Valori consigliati:**

| Scenario | Timeout LAN | Timeout porte |
|---|---|---|
| Rete locale veloce (Gigabit) | 1-2 s | 0.5-1 s |
| Rete Wi-Fi domestica | 2-3 s | 1-2 s |
| Rete con molti host o lenta | 4-5 s | 2-3 s |
| Host remoto (fuori LAN) | N/A | 3-5 s |

### Opzioni avanzate di port scan

#### Range di porte personalizzabile

Invece di scansionare solo le porte predefinite, è possibile specificare un range personalizzato:

| Modalità | Sintassi | Esempio |
|---|---|---|
| Porta singola | `N` | `80` |
| Range continuo | `N-M` | `1-1024` |
| Lista | `N,M,K` | `22,80,443,8080` |
| Misto | `N,M-K` | `22,80-90,443` |

> **Attenzione:** scansionare un range ampio (es. 1-65535) su molti host richiede tempi molto lunghi. Si consiglia di limitarsi alle porte di interesse.

#### Tipo di scan

Sniffable supporta diverse modalità di scansione TCP:

| Tipo | Descrizione | Vantaggi | Svantaggi |
|---|---|---|---|
| **SYN Scan** (default) | Invia un SYN, analizza la risposta (SYN-ACK = aperta, RST = chiusa). Non completa l'handshake. | Veloce, meno invasivo, non registrato nei log applicativi | Richiede privilegi root |
| **Full Connect** | Completa il three-way handshake TCP tramite le socket del sistema operativo. | Non richiede root, più affidabile | Più lento, registrato nei log |
| **UDP Scan** | Invia un datagramma UDP vuoto, analizza la risposta ICMP "port unreachable" (chiusa) o l'assenza di risposta (aperta/filtrata). | Scopre servizi UDP (DNS, DHCP, SNMP) | Molto lento, risultati ambigui |

---

## 7. Il Tasto Download

Il tasto **Download** è disponibile nella sezione **Packets** e permette di esportare i dati catturati in locale per analisi successive o archiviazione.

### Formati di esportazione

Sniffable supporta il download in entrambi i formati principali:

#### PCAP (Packet Capture)

Il formato `.pcap` è lo standard de facto per l'archiviazione di pacchetti di rete. I file PCAP possono essere aperti con:

- **Wireshark** (analisi grafica avanzata)
- **tcpdump** (analisi da terminale)
- **Scapy stesso** (`rdpcap("file.pcap")`)
- Qualsiasi altro tool di analisi di rete

Quando si sceglie il formato PCAP, il backend serializza i pacchetti catturati utilizzando le API di Scapy:

```python
from scapy.utils import wrpcap
wrpcap("capture.pcap", packets)
```

Il file viene quindi inviato al frontend come blob binario via WebSocket (o tramite un endpoint HTTP dedicato), che lo presenta all'utente come download del browser/Electron.

#### Report testuale (TXT / JSON / CSV)

Il formato testuale è più leggibile e adatto per:
- Archiviazione leggera (file più piccoli del PCAP)
- Importazione in fogli di calcolo o database
- Condivisione via email o chat senza strumenti specializzati

A seconda del formato scelto:

**TXT:** log human-readable con un pacchetto per riga nel formato:
```
[2025-01-15 10:32:01.123] 192.168.1.10 → 8.8.8.8  DNS  74 bytes
[2025-01-15 10:32:01.456] 8.8.8.8 → 192.168.1.10  DNS  142 bytes
```

**JSON:** array di oggetti con tutti i campi dei pacchetti, facilmente importabile in Python, JavaScript o qualsiasi altro linguaggio:
```json
[
  {
    "timestamp": "2025-01-15T10:32:01.123Z",
    "src": "192.168.1.10",
    "dst": "8.8.8.8",
    "protocol": "DNS",
    "length": 74,
    "layers": { ... }
  }
]
```

**CSV:** formato tabellare per importazione in Excel o analisi con pandas:
```
timestamp,src,dst,protocol,length
2025-01-15T10:32:01.123Z,192.168.1.10,8.8.8.8,DNS,74
```

### Comportamento del download

1. L'utente preme il tasto **Download** nella sezione Packets.
2. Se supportato, viene mostrato un dialogo per scegliere il formato (PCAP, TXT, JSON, CSV).
3. Il frontend invia al backend la richiesta di esportazione con il formato selezionato.
4. Il backend prepara il file e lo invia come risposta WebSocket (o tramite endpoint HTTP).
5. Electron (o il browser) presenta la finestra di dialogo "Salva file" e l'utente sceglie la destinazione.

> **Nota:** il download include solo i pacchetti attualmente presenti nella lista (quelli non ancora rimossi con Clear). Se si vuole un sottoinsieme, è possibile filtrare prima di scaricare.

---

## 8. Comunicazione WebSocket

Il WebSocket è il canale di comunicazione centrale di Sniffable. Tutti i comandi e tutti i dati fluiscono attraverso di esso in formato JSON.

### Struttura dei messaggi

**Comandi (frontend → backend):**

```json
{
  "action": "nome_azione",
  "param1": "valore1",
  "param2": "valore2"
}
```

**Risposte ed eventi (backend → frontend):**

```json
{
  "event": "nome_evento",
  "status": "ok" | "error",
  "data": { ... }
}
```

### Azioni supportate

| Azione | Descrizione |
|---|---|
| `start_sniff` | Avvia lo sniffing con i parametri forniti |
| `stop_sniff` | Ferma lo sniffing |
| `scan_lan` | Avvia la scansione ARP della rete specificata |
| `scan_ports` | Avvia il port scan sull'host specificato |
| `send_packet` | Costruisce e invia il pacchetto descritto nel payload |
| `download` | Esporta i pacchetti catturati nel formato specificato |
| `get_interfaces` | Richiede la lista delle interfacce di rete disponibili |

### Gestione degli errori

Se il backend non riesce a completare un'operazione (es. interfaccia non trovata, permessi insufficienti), invia un evento di errore:

```json
{
  "event": "error",
  "action": "start_sniff",
  "message": "Interfaccia eth0 non trovata o non accessibile",
  "code": "INTERFACE_NOT_FOUND"
}
```

Il frontend mostra il messaggio di errore all'utente tramite una notifica o un banner.

---

## 9. Configurazione Hardware

### Target principale: Raspberry Pi 5

Sniffable è ottimizzato per girare su Raspberry Pi 5 con schermo touch, offrendo un'esperienza autonoma e portatile.

| Componente | Specifiche consigliate |
|---|---|
| **SBC** | Raspberry Pi 5 |
| **CPU** | ARM Cortex-A76, 4 core @ 2.4 GHz |
| **RAM** | 4 GB (minimo) / 8 GB (raccomandato) |
| **Storage** | microSD ≥ 32 GB (Class 10 / A2) o SSD via M.2 HAT |
| **Display** | Raspberry Pi Touch Display 2 (720×1280) o qualsiasi display HDMI touch |
| **OS** | Raspberry Pi OS Bookworm (64-bit) |
| **Rete** | Ethernet integrata (1 Gbps) + adattatore Wi-Fi/USB opzionale |
| **Alimentazione** | USB-C 5V/5A |

#### Ottimizzazioni touch

L'interfaccia è progettata per essere usata con le dita su uno schermo da 7-10 pollici:
- Pulsanti di dimensione adeguata al touch (minimo 44×44 px)
- Nessun hover-only interaction
- Liste scorrevoli con momentum scroll
- Font leggibili a distanza ravvicinata

### PC Desktop / Laptop

| Componente | Specifiche |
|---|---|
| **OS** | Linux (Ubuntu, Debian, Kali, Arch), macOS ≥ 12, Windows 10/11 |
| **CPU** | Qualsiasi x86_64 moderno |
| **RAM** | 2 GB minimo, 4 GB raccomandati |
| **Rete** | Qualsiasi interfaccia supportata da Scapy / libpcap |

---

## 10. Note di Sicurezza e Uso Responsabile

> ⚠️ **AVVISO IMPORTANTE**
>
> Sniffable è uno strumento pensato esclusivamente per scopi **didattici, di ricerca e per l'analisi di reti di propria proprietà o su cui si dispone di autorizzazione esplicita e documentata**.

### Legalità

- **Sniffing di rete**: l'intercettazione non autorizzata di comunicazioni di rete è illegale in molti paesi (in Italia è regolata dall'art. 617-quater del Codice Penale). Usare Sniffable solo su reti proprie o previa autorizzazione scritta del proprietario.
- **Port scanning**: la scansione di porte su sistemi non propri senza autorizzazione può configurare reati informatici (art. 615-ter c.p. in Italia, Computer Fraud and Abuse Act negli USA).
- **Packet sending**: l'invio di pacchetti con IP/MAC falsificati (spoofing) su reti non autorizzate è perseguibile legalmente.

### Buone pratiche

- Non utilizzare Sniffable su reti pubbliche (aeroporti, hotel, università) senza autorizzazione esplicita.
- Non intercettare traffico di terzi: le comunicazioni altrui sono protette dalla normativa sulla privacy.
- Documentare sempre le attività di analisi con data, ora e rete analizzata.
- In ambito aziendale, ottenere sempre l'autorizzazione scritta del responsabile IT o del proprietario della rete.

### Limitazioni tecniche

- Sniffable richiede **privilegi di root/amministratore** per accedere all'interfaccia di rete a basso livello. Non eseguire il server Python come root in ambienti di produzione senza le dovute precauzioni di sicurezza.
- Su reti switched (la stragrande maggioranza delle reti moderne), lo sniffing passivo cattura solo il traffico diretto al dispositivo e il traffico broadcast/multicast, non l'intero traffico della rete.
- Per catturare il traffico di altri host su una rete switched è necessario utilizzare tecniche come il port mirroring (configurazione sullo switch) o l'ARP poisoning (attività offensiva, illegale senza autorizzazione).

---

## 11. Glossario

| Termine | Definizione |
|---|---|
| **ARP** | Address Resolution Protocol. Protocollo di livello 2 che associa indirizzi IP a indirizzi MAC. Usato da Sniffable per la scoperta degli host sulla LAN. |
| **CIDR** | Classless Inter-Domain Routing. Notazione compatta per indicare una rete IP e la sua subnet mask (es. `192.168.1.0/24`). |
| **EtherType** | Campo nel frame Ethernet che identifica il protocollo di livello 3 incapsulato (es. `0x0800` = IPv4, `0x0806` = ARP). |
| **Full Connect Scan** | Tipo di port scan che completa il three-way handshake TCP prima di chiudere la connessione. Affidabile ma facilmente rilevabile. |
| **ICMP** | Internet Control Message Protocol. Usato per messaggi di controllo (es. ping, port unreachable). |
| **libpcap** | Libreria C per la cattura di pacchetti di rete a basso livello. Usata internamente da Scapy su Linux/macOS. |
| **MAC Address** | Media Access Control. Identificatore univoco a 48 bit assegnato a ogni interfaccia di rete. |
| **Npcap** | Versione Windows di libpcap, necessaria per il funzionamento di Scapy su Windows. |
| **OUI** | Organizationally Unique Identifier. I primi 3 byte di un MAC address, che identificano il produttore dell'interfaccia. |
| **PCAP** | Packet Capture. Formato file standard per l'archiviazione di pacchetti di rete catturati. |
| **Port Mirroring** | Funzionalità degli switch gestiti che permette di copiare tutto il traffico di una porta verso un'altra porta (per sniffing autorizzato). |
| **Scapy** | Libreria Python per la manipolazione di pacchetti di rete. Permette di costruire, inviare, ricevere e analizzare pacchetti a qualsiasi livello del modello OSI. |
| **Sniffing** | Cattura e analisi del traffico di rete in transito su un'interfaccia. |
| **Spoofing** | Falsificazione di campi identificativi (IP, MAC) nei pacchetti di rete. |
| **SYN Scan** | Tipo di port scan che invia solo il pacchetto SYN iniziale e analizza la risposta senza completare l'handshake. Veloce e meno invasivo. |
| **Three-way handshake** | Sequenza di scambio (SYN → SYN-ACK → ACK) necessaria per stabilire una connessione TCP. |
| **TTL** | Time To Live. Campo IP che indica il numero massimo di hop che un pacchetto può attraversare prima di essere scartato. |
| **WebSocket** | Protocollo di comunicazione full-duplex su connessione TCP persistente, che permette scambio bidirezionale di messaggi tra client e server. |

---

## 12. FAQ

**Q: Perché lo sniffer non cattura nessun pacchetto?**
A: Verificare di aver avviato il server Python con privilegi di root (`sudo`). Verificare che l'interfaccia di rete selezionata sia quella corretta e sia attiva. Su Windows, assicurarsi che Npcap sia installato.

**Q: La scansione LAN non trova alcuni dispositivi che so essere connessi.**
A: Alcuni dispositivi (specialmente smartphone e sistemi moderni) ignorano le richieste ARP provenienti da host sconosciuti o hanno funzionalità di privacy che randomizzano il MAC address. Aumentare il timeout di scan può aiutare.

**Q: Il port scan è molto lento.**
A: Ridurre il range di porte scansionate, abbassare il timeout se la rete è veloce, o limitare la scansione agli host di interesse invece di scansionare l'intera subnet.

**Q: Posso usare Sniffable su una VPN?**
A: Sì, selezionando l'interfaccia virtuale della VPN (es. `tun0`). Lo sniffing catturerà il traffico che passa attraverso il tunnel VPN.

**Q: Il file PCAP scaricato non si apre in Wireshark.**
A: Verificare che il download sia completo (file non corrotto). Provare ad aprire il file con `tcpdump -r file.pcap` da terminale per un messaggio di errore più dettagliato.

**Q: Posso eseguire il backend su un host diverso dal frontend?**
A: Sì. Il backend è completamente indipendente e si connette via WebSocket. È sufficiente configurare l'URL del WebSocket nel frontend affinché punti all'indirizzo IP del backend remoto (es. `ws://192.168.1.50:8765`).

---

*Documentazione generata per Sniffable v1.0 — 2025*
*Programma scritto in Python con ausilio di [Scapy](https://scapy.net/)*