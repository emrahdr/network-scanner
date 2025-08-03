import scapy.all as scapy
import socket
import netifaces

def port_tarama(ip, portlar):
    acik_portlar = []
    for port in portlar:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            sonuc = sock.connect_ex((ip, port))
            if sonuc == 0:
                acik_portlar.append(port)
            sock.close()
        except:
            pass
    return acik_portlar

def ag_bilgisi_al():
    # Kali'deki varsayılan ağ arayüzünü bul
    arayuzler = netifaces.interfaces()
    for iface in arayuzler:
        if iface == 'lo':
            continue
        try:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                ip = ip_info['addr']
                netmask = ip_info['netmask']
                return ip, netmask
        except:
            continue
    return None, None

def cidr_hesapla(ip, netmask):
    import ipaddress
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    return str(network)

def tara(ip_araligi):
    print(f"Ağ taraması başlıyor: {ip_araligi}")
    istek = scapy.ARP(pdst=ip_araligi)
    yayin = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    paket = yayin / istek

    cevap = scapy.srp(paket, timeout=2, verbose=False)[0]

    for paket in cevap:
        ip = paket[1].psrc
        mac = paket[1].hwsrc
        print(f"IP: {ip} \t MAC: {mac}")

        portlar = [22, 80, 443, 8080]
        acik_portlar = port_tarama(ip, portlar)

        if acik_portlar:
            print(f"  Açık portlar: {', '.join(str(p) for p in acik_portlar)}")
        else:
            print("  Açık port bulunamadı.")
        print()

if __name__ == "__main__":
    try:
        ip, netmask = ag_bilgisi_al()
        if ip is None:
            print("Ağ bilgisi alınamadı!")
        else:
            cidr = cidr_hesapla(ip, netmask)
            tara(cidr)
    except KeyboardInterrupt:
        print("\nTarama iptal edildi.")
