import dpkt
import sys
import socket
IP_Mac = {"192.168.0.100": "7c:d1:c3:94:9e:b8", "192.168.0.103":"d8:96:95:01:a5:c9", "192.168.0.1":"f8:1a:67:cd:57:6e"}
def construct_Str(ints, condition):
    if condition == "IP":
        listInt = list(ints)
        IPstr = ""
        first = True
        for int in listInt:
            if first != True:
                IPstr += "."
            else:
                first = False
            IPstr += str(int)
        return IPstr
    else:
        Macstr = ""
        first = True
        hex = ints.hex()
        index = 0
        while index < len(hex):
            if first != True:
                Macstr += ":"
            else:
                first = False
            Macstr += hex[index:index+2]
            index += 2
        return Macstr



def check_spoof(counter, ethernetArp):
    IP = ethernetArp.spa
    IP = construct_Str(IP, "IP")
    Mac = ethernetArp.sha
    Mac = construct_Str(Mac, "MAC")
    dstMac = ethernetArp.tha
    dstMac = construct_Str(dstMac, "MAC")

    if IP in IP_Mac and IP_Mac[IP] != Mac:
        print("ARP spoofing!")
        print("Src MAC: " +Mac)
        print("Dst MAC: "+dstMac)
        print("Packet number: "+str(counter))

def add_port_scan(ethrData,port_scan_dict, num, udp):
    if udp or ethrData.data.flags == dpkt.tcp.TH_SYN:
        IPdst = ethrData.dst
        port = ethrData.data.dport
        if ethrData.dst not in port_scan_dict.keys():
            port_scan_dict[IPdst] = {}
            port_scan_dict[IPdst][port] = num
        else:
            if port not in port_scan_dict[IPdst].keys():
                port_scan_dict[IPdst][port] = num



def print_port_scan(port_scan_dict):
    for IPdst in port_scan_dict.keys():
        if len(port_scan_dict[IPdst]) >= 100:
            # https://stackoverflow.com/questions/25370010/parsing-ip-address-with-dpkt
            print("Port scan!")
            print("Dst IP: "+ socket.inet_ntoa(IPdst))
            packet_list = []
            for packet in port_scan_dict[IPdst].values():
                packet_list.append(packet)
            # https://stackoverflow.com/questions/11178061/print-list-without-brackets-in-a-single-row
            print("Packet number:", end=" ")
            print(str(packet_list)[1:-1])

def check_SYN(ethrData, timeStamp, TCP_SYN_flood_dict, num):
    if ethrData.data.flags == dpkt.tcp.TH_SYN:
        IPdst = ethrData.dst
        port = ethrData.data.dport
        if IPdst in TCP_SYN_flood_dict.keys():
            if TCP_SYN_flood_dict[IPdst]["flooded"]:
                return

            TCP_SYN_flood_dict[IPdst]["list"].append([timeStamp, port, num])
            if len(TCP_SYN_flood_dict[IPdst]["list"]) >= 100:
                if timeStamp - TCP_SYN_flood_dict[IPdst]["list"][0][0] <= 1:
                    print("SYN floods!")
                    print("Dst IP: "+ socket.inet_ntoa(IPdst))
                    print("Dst Port: " + str(port))
                    packet_list = []
                    for packet in TCP_SYN_flood_dict[IPdst]["list"]:
                        packet_list.append(packet[2])
                    print("Packet number:", end=" ")
                    print(str(packet_list)[1:-1])
                    TCP_SYN_flood_dict[IPdst]["flooded"] = True
                else:
                    TCP_SYN_flood_dict[IPdst]["list"].pop(0)
        else:
            TCP_SYN_flood_dict[IPdst] = {"flooded": False, "list": [[timeStamp, port, num]]}


def main(filename):
    with open(filename,'rb') as file:
        port_scan_dict = {}
        TCP_SYN_flood_dict = {}
        pcap = dpkt.pcap.Reader(file)
        counter = 0
        for timeStamp, buffer in pcap:
            ethernet = dpkt.ethernet.Ethernet(buffer)
            ethrData = ethernet.data
            if type(ethrData) is dpkt.arp.ARP:
                check_spoof(counter, ethrData)
            elif type(ethrData) is dpkt.ip.IP:
                IPData = ethrData.data
                if type(IPData) is dpkt.tcp.TCP:
                    add_port_scan(ethrData,port_scan_dict, counter, False)
                    check_SYN(ethrData, timeStamp, TCP_SYN_flood_dict, counter)
                elif type(IPData) is dpkt.udp.UDP:
                    add_port_scan(ethrData,port_scan_dict, counter, True)
            counter+=1
        print_port_scan(port_scan_dict)



if __name__ == '__main__':
    main(sys.argv[1])