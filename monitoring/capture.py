# https://www.wireshark.org/download.html
#download npcap
    # npcap can save the livecapture to files to download instead which could be used for training data later
import pyshark

#instance of packet capture
capture = pyshark.LiveCapture(interface='Wi-Fi', output_file='capture.pcap') #fix i don't know what ip to look for yet

capture.set_debug()

#start capturing packets
capture.sniff(timeout=10) 

for packet in capture:
    print(packet)

capture.close()


#try not to print every packet:
#ideas:
    # coun the packets\
    #print a summary
    #