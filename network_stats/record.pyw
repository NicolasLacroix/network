from scapy.all import *
import time
import sqlite3

# TODO: voir performances


def logPacket(pkt):
    # TODO: verifier ip src and ip dst
    print("new insertion")
    conn = sqlite3.connect('communications.db')
    c = conn.cursor()
    # pkt.layers[0] = data link
    if len(pkt.layers()) < 3:
        return  # TODO: a voir
    layer_name = pkt.layers()[2]._name  # transport layer protocol
    c.execute(
        "INSERT INTO communication(date_com, protocole, ip_src, ip_dst, additional_data) VALUES (?, ?, ?, ?, ?)", (pkt.time, layer_name, pkt.src, pkt.dst, pkt.lastlayer().name))
    # Saving data into database
    conn.commit()


def main():
    t = AsyncSniffer(prn=logPacket, store=False)
    t.start()
    time.sleep(1000000)  # todo: change to keep running without time.sleep
    # We can also close the connection if we are done with it.
    # Just be sure any changes have been committed or they will be lost.
    conn.close()

if __name__ == '__main__':
    main()
