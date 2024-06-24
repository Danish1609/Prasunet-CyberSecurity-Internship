from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

def packet_callback(packet):
    try:
        # Check if the packet has an IP layer
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto

            logging.info("\nPacket: %s", packet.summary())
            logging.info("Source IP: %s", ip_src)
            logging.info("Destination IP: %s", ip_dst)
            
            if protocol == 6:  # TCP protocol
                if TCP in packet:
                    logging.info("Protocol : TCP")
                    logging.info("Source Port : %s", packet[TCP].sport)
                    logging.info("Destination Port : %s", packet[TCP].dport)
            elif protocol == 17:  # UDP protocol
                if UDP in packet:
                    logging.info("Protocol : UDP")
                    logging.info("Source Port : %s", packet[UDP].sport)
                    logging.info("Destination Port : %s", packet[UDP].dport)
            elif protocol == 1:  # ICMP protocol
                if ICMP in packet:
                    logging.info("Protocol : ICMP")
            else:
                logging.info("Protocol : Other")
    except Exception as e:
        logging.error("Error processing packet: %s", e)

# Start sniffing
logging.info("\nStarting packet capture")
try:
    sniff(prn=packet_callback, count=10)
except KeyboardInterrupt:
    logging.info("\nPacket capture interrupted by user")
except Exception as e:
    logging.error("\nAn error occurred during packet capture: %s", e)
finally:
    logging.info("\nPacket capture completed\n")
