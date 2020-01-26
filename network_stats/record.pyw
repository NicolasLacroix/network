from scapy.all import *
import time
import sqlite3

# TODO: voir performances


def logPacket(pkt):
    # TODO: verifier ip src and ip dst
    # print("new insertion")
    # print(pkt.layers()[-1]._name)
    conn = sqlite3.connect('communications.db')
    c = conn.cursor()
    # pkt.layers[0] = data link
    if len(pkt.layers()) < 3:
        return  # TODO: a voir
    layer_name = pkt.layers()[2]._name  # transport layer protocol
    try:
        c.execute(
            "INSERT INTO communication(date_com, protocole, ip_src, ip_dst, port, content, additional_data) VALUES (?, ?, ?, ?, ?, ?, ?)", (pkt.time, layer_name, pkt.src, pkt.dst, pkt.dport, pkt.summary(), pkt.lastlayer().name))
    except:
        c.execute(
            "INSERT INTO communication(date_com, protocole, ip_src, ip_dst, content, additional_data) VALUES (?, ?, ?, ?, ?, ?)", (pkt.time, layer_name, pkt.src, pkt.dst, pkt.summary(), pkt.lastlayer().name))
    # Saving data into database
    conn.commit()


def filterRTP(pkt):
    if pkt.haslayer(UDP):
        print('===')
        print("UDP : ", pkt[UDP].dport)
        print(pkt[IP].src, " >> ", pkt[IP].dst)
        print('===')
        # time.sleep(0.5)
        if pkt["UDP"].dport == 5016:  # Make sure its actually RTP
            pkt["UDP"].payload = RTP(pkt["Raw"].load)
            print(pkt)
            # logPacket(pkt)
    elif pkt.haslayer(TCP):
        print('===')
        print("TCP : ", pkt["TCP"].dport)
        print(pkt[IP].src, " >> ", pkt[IP].dst)
        print('===')
        # time.sleep(0.5)
        if pkt["TCP"].dport == 554:  # Make sure its actually RTP
            pkt["TCP"].payload = RTP(pkt["Raw"].load)
            print(pkt)
            # logPacket(pkt)
    else:
        print("===")
        print(pkt.summary())
        print("===")
    logPacket(pkt)


def main():
    t = AsyncSniffer(prn=filterRTP, store=False)
    t.start()
    time.sleep(1000000)  # todo: change to keep running without time.sleep
    # We can also close the connection if we are done with it.
    # Just be sure any changes have been committed or they will be lost.
    conn.close()

if __name__ == '__main__':
    main()
