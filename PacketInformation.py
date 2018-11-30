import datetime
import sys
import argparse
import socket
from struct import *
from PythonSniffer import PythonSniffer
from enum import Enum


class PacketInformation:

    #The packet is passed from the PythonSniffer and processed in different format for your convenience.
    def __init__(self, bytes_tuple_info):
        self.bytes_tuple_info = bytes_tuple_info
        self.packet_byte_array = bytes_tuple_info[0]
        self.packet_representation = dict()

        self.byte_count = 0
        for b in self.packet_byte_array:
                self.packet_representation[ self.byte_count + 1 ] = format(self.packet_byte_array[ self.byte_count ], '02x')
                self.byte_count = self.byte_count + 1

    # This function converts a byte string into a proper MAC address format
    def macify(self, mac_string):
        return ':'.join('%02x' % b for b in mac_string)

    # This function converts a value into a hexadecimal format (e.g. 0x0800)
    def hexify(self, value, sig_figs=4):
        return "0x{:04x}".format(value)

    ####################################################################################################################
    ####################################################################################################################
    ### Link Layer Processing
    ### Get the Ethernet Frame details. Usually this is contained in the first 14 bytes of the packet.
    ### You need to process the following types of Link Layer frames
    ### 1. Ethernet

    # See https://en.wikipedia.org/wiki/Ethernet_frame for details
    def EthernetDetails(self):

        eth_details = {
            'DestMAC' : None,
            'SourceMAC' : None,
            'EtherType' : None
        }
        macSize = 5
        etherSize = 2
        beginDst = 0
        endDst = beginDst + macSize
        beginSrc = endDst + 1
        endSrc = beginSrc + macSize
        beginEther = endSrc + 1
        endEther = beginEther + etherSize
        etherVal = 0
        etherString = ''
        # TODO: Complete this function by extracting the ethernet header and assigning
        # the values created in the above dictionary

        #This may be correctly taking out the dest MAC address, honestly not sure
        eth_details['DestMAC'] = self.macify(self.packet_byte_array[beginDst:endDst])
        #This is the current attempt to get out the source MAC address, again
        #unsure of the current functionality.
        eth_details['SourceMAC'] = self.macify(self.packet_byte_array[beginSrc:endSrc])
        #This is the current attempt to retrieve the etherType, as I'm sure you
        #are shocked to hear, I am also unsure if this is correct.
        for i in self.packet_byte_array[beginEther:endEther]:
            etherVal = etherVal << 8
            etherVal = etherVal + i

        etherString = self.hexify(etherVal)
        eth_details['EtherType'] = etherString

        return eth_details


    ####################################################################################################################
    ####################################################################################################################
    ### Network Layer Processing
    ### You need to process the following Network Layer datagram. You can determine what type of Network Layer datagram
    ### is in a packet using Ethernet's EtherType field
    ### 1. IPv4
    ### 2. ARP


    ### If this packet is IPv4, then exctract IPv4 information like source, destination and protocol.
    ### The information is found in the next 20 bytes after the 14 byte MAC address.
    ### See https://en.wikipedia.org/wiki/IPv4 for details
    def IPPacketDetails(self):
        #    0               1               2               3
        #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #   |Version|  IHL  |Type of Service|         Total  Length         |
        #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #   |        Identification         |Flags|     Fragment  Offset    |
        #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #   | Time to Live  |   Protocol    |        Header Checksum        |
        #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #   |                        Source Address                         |
        #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #   |                      Destination Address                      |
        #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        # Populate the ip_details list with values extracted from the packet.
        ip_details = {
            "IPVersion" : None,
            "IHL" : None,
            "Length" : None,
            "Identifier" : None,
            "Flag_DF" : None,
            "Flag_MF" : None,
            "FragmentOffset" : None,
            "TTL" : None,
            "ProtocolNumber" : None,
            "Checksum" : None,
            "SourceAddr" : None,
            "DestAddr" : None
        }
        # Extract information from the IPv4 header of the packet.

        # First, we're going to unpack the data. This converts bytes into their specific variable type so we can work with them
        # * The leading ! tells the unpack function that this is network data, with is represented in a Big-Endian format
        # * BBHHHBBH4s4s says we want: 1) an unsigned char, 2) an unsigned char, 3) an unsigned short, 4) an unsigned short,
        #   5) an unsigned short, 6) an unsigned char, 7) an unsigned char, 8) an unsigned short, 9) a 4 char array,
        #   10) a 4 char array
        # * If you look at the IPv4 header above, you can see this (mostly) maps to the fields. Fields that are SMALLER
        #   than one byte (like Version) can't be handled directly using unpack, so we'll deal with that next
        iph = unpack('!BBHHHBBH4s4s', self.bytes_tuple_info[0][14:34])

        # The version information is contained in iph[0], as the four upper bits in this char
        version_ihl = iph[0]
        # We can extract those four bits using this command, which shifts the bits of the char by 4 places
        # This will eliminate the bits associated with IHL and get the remaining bits in the desired lower position
        ip_details["IPVersion"] = version_ihl >> 4
        # Finally, we extract the IHL value by bit-wise ANDing the version_ihl value with 0xF, which is 00001111
        # This will set the bits associated with the version # to 0 and preseve any bits set to 1 in the IHL field
        ip_details["IHL"] = version_ihl & 0xF

        # The header length = IFL * 4 (in bytes)
        # This should result in 20 for most packets, since they won't have an options field
        header_length = ip_details["IHL"] * 4

        # Extract the total length, no processing
        ip_details['Length'] = iph[2]

        # Extract the fragment ID value, no processing
        ip_details['Identifier'] = iph[3]

        # Extract the Don't Fragment flag
        ip_details['Flag_DF'] = iph[4] & 0x40

        # Extract the More Fragments flag
        ip_details['Flag_MF'] = iph[4] & 0x20

        # Extract the fragment offset, multiply by 8 to get it in bytes
        ip_details['FragmentOffset'] = (iph[4] & 0x1F) * 8

        # Extract the TTL value, no processing
        ip_details['TTL'] = iph[5]

        # Extract the protocol information, no processing
        ip_details['ProtocolNumber'] = iph[6]

        # Extract the source IP address using the socket.inet_ntoa() function
        ip_details['SourceAddr'] = socket.inet_ntoa(iph[8])

        # Extract the destination IP address using the socket.inet_ntoa() function
        ip_details['DestAddr'] = socket.inet_ntoa(iph[9])

        return ip_details

    # See https://en.wikipedia.org/wiki/Address_Resolution_Protocol for details
    def ARPPacketDetails(self):
        arp_details = {
            'HTYPE': None,
            'PTYPE': None,
            'HLEN': None,
            'PLEN' : None,
            'OPER' : None,
            'SHA' : None,
            'SPA' : None,
            'THA' : None,
            'TPA' : None
        }


        # TODO: Complete this function by extracting the ARP header and assigning
        # the values created in the above dictionary
        beginInd = 15
        dataArr = [0,1,2,3,4,5,6,7,8]
        storeAns = [0,1,2,3,4,5,6,7,8]

        hTypeInd = 0
        dataArr[hTypeInd]= 2

        pTypeInd = 1
        dataArr[pTypeInd] = 2

        hLenInd = 2
        dataArr[hLenInd] = 1

        pLenInd = 3
        dataArr[pLenInd] = 1

        operInd = 4
        dataArr[operInd] = 2

        shaInd = 5
        dataArr[shaInd] = 6

        spaInd = 6
        dataArr[spaInd] = 4

        thaInd = 7
        dataArr[thaInd] = 6

        tpaInd = 8
        dataArr[tpaInd] = 4

        for i in range(0,9):
            #Find the end value
            endInd = beginInd + dataArr[i]
            storeAns[i] = 0
            for p in self.packet_byte_array[beginInd:endInd]:
                storeAns[i] = storeAns[i] << 8
                storeAns[i] = storeAns[i] + p
            beginInd = beginInd + 1
        arp_details['HTYPE'] = self.hexify(storeAns[hTypeInd])
        arp_details['PTYPE'] = self.hexify(storeAns[pTypeInd])
        arp_details['HLEN'] = self.hexify(storeAns[hLenInd])
        arp_details['PLEN'] = self.hexify(storeAns[pLenInd])
        arp_details['OPER'] = self.hexify(storeAns[operInd])
        arp_details['SHA'] = self.hexify(storeAns[shaInd])
        arp_details['SPA'] = self.hexify(storeAns[spaInd])
        arp_details['THA'] = self.hexify(storeAns[thaInd])
        arp_details['TPA'] = self.hexify(storeAns[tpaInd])

        return arp_details

    ####################################################################################################################
    ####################################################################################################################
    ### Transport Layer Processing
    ### You need to process the following Transport Layer segments. You can determine what type of Transport Layer segment
    ### is in a packet using IPv4's Protocol field
    ### 1. IPv4
    ### 2. ARP


    def TCPInfo(self):
        tcp_details = {
            'SourcePort' : None,
            'DestPort' : None,
            'SeqNum' : None,
            'ACKNum' : None,
            'ACK' : None,
            'RST' : None,
            'SYN' : None,
            'FIN' : None,
            'RcvWindow' : None,
            'Checksum' : None
        }

        # TODO: Complete this function by extracting the TCP header and assigning
        # the values created in the above dictionary. Note that ACK, RST, SYN, and FIN are 1 bit flags
        beginInd = 35
        sizeArr = [0,1,2,3,4,5,6,7]
        storeAns = [0,1,2,3,4,5,6,7]

        srcInd = 0
        sizeArr[srcInd]= 2

        destInd = 1
        sizeArr[destInd] = 2

        seqInd = 2
        sizeArr[seqInd] = 4

        ackNumInd = 3
        sizeArr[ackNumInd] = 4

        dataInd = 4
        sizeArr[ackNumInd] = 1

        bitsInd = 5
        sizeArr[ackNumInd] = 4

        rcvInd = 6
        sizeArr[rcvInd] = 2

        checkInd = 7
        sizeArr[checkInd] = 2

        for i in range(0,8):
            #Find the end value
            endInd = beginInd + sizeArr[i]
            storeAns[i] = 0
            for p in self.packet_byte_array[beginInd:endInd]:
                storeAns[i] = storeAns[i] << 8
                storeAns[i] = storeAns[i] + p
            beginInd = beginInd + 1

        tcp_details['SourcePort'] = int(self.hexify(storeAns[srcInd]), 16)
        tcp_details['DestPort'] = int(self.hexify(storeAns[destInd]), 16)
        tcp_details['SeqNum'] = self.hexify(storeAns[seqInd])
        tcp_details['ACKNum'] = self.hexify(storeAns[ackNumInd])
        tcp_details['ACK'] = self.hexify(((storeAns[bitsInd] >> 4) & 1))
        tcp_details['RST'] = self.hexify(((storeAns[bitsInd] >> 2) & 1))
        tcp_details['SYN'] = self.hexify(((storeAns[bitsInd] >> 1) & 1))
        tcp_details['FIN'] = self.hexify((storeAns[bitsInd] & 1))
        tcp_details['RcvWindow'] = self.hexify(storeAns[rcvInd])
        tcp_details['Checksum'] = self.hexify(storeAns[checkInd])


        return tcp_details


    def UDPInfo(self):
        udp_details = {
            'SourcePort': None,
            'DestPort': None,
            'Length': None,
            'Checksum': None
        }

        # TODO: Complete this function by extracting the UDP header and assigning
        # the values created in the above dictionary.
        beginInd = 35
        sizeArr = [0,1,2,3]
        storeAns = [0,1,2,3]

        srcInd = 0
        sizeArr[srcInd]= 2

        destInd = 1
        sizeArr[destInd] = 2

        lengthInd = 2
        sizeArr[lengthInd] = 4

        checkInd = 3
        sizeArr[checkInd] = 4

        for i in range(0,4):
            #Find the end value
            endInd = beginInd + sizeArr[i]
            storeAns[i] = 0
            for p in self.packet_byte_array[beginInd:endInd]:
                storeAns[i] = storeAns[i] << 8
                storeAns[i] = storeAns[i] + p
            beginInd = beginInd + 1

        udp_details['SourcePort'] = int(self.hexify(storeAns[srcInd]), 16)
        udp_details['DestPort'] = int(self.hexify(storeAns[destInd]), 16)
        udp_details['Length'] = self.hexify(storeAns[lengthInd])
        udp_details['Checksum'] = self.hexify(storeAns[checkInd])


        return udp_details




    ####################################################################################################################
    ####################################################################################################################
    ### Printing the contents of the sniffed packets

    def print_packet_information(self, print_filter='all'):

        # Printing Packets Content in Hexadecimal Format
        if print_filter == 'all':
            print("Interface : " + self.bytes_tuple_info[1][0])
            print( self.format_binary_array ( self.bytes_tuple_info[1][4] ) )
            print(self.format_binary_array(self.packet_byte_array))

        print("=========== PACKET ===========")
        print("Size : " + str( len(self.packet_byte_array)) + " Bytes")

        self.print_ethernet_information(packet_filter)


    def print_ethernet_information(self, print_filter='all'):
        print('---- Link Layer Information ----')

        eth_result = self.EthernetDetails()
        print("\tDestination MAC: " + eth_result["DestMAC"])
        print("\tSource MAC: " + eth_result["SourceMAC"])
        print("\tEtherType: " + eth_result["EtherType"])

        ip4Val = '0x0800'
        ip6Val = '0x86DD'
        arpVal = '0x0806'
        # TODO: Call the appropriate print function based on the EtherType value
        #  * self.print_IPv4_information(print_filter)
        if eth_result['EtherType'] == ip4Val:
            self.print_IPv4_information(print_filter)
        #  * self.print_ARP_information(print_filter)
        elif eth_result['EtherType'] == arpVal:
            self.print_ARP_information(print_filter)
        #  * self.print_IPv6_information(print_filter)
        elif eth_result['EtherType'] == ip6Val:
            self.print_IPv6_information(print_filter)


    def print_IPv4_information(self, print_filter='all'):
        print('---- Network Layer Information ----')

        ip_header_info = self.IPPacketDetails()
        print("\tIP Version : " + str(ip_header_info['IPVersion']))
        print("\tHeader Length : " + str(ip_header_info['IHL']))
        print("\tData Length : " + str(ip_header_info['Length']))
        print("\tFragment ID: " + str(ip_header_info['Identifier']))
        print("\tDon't Fragment Flag : " + str(ip_header_info['Flag_DF']))
        print("\tMore Fragments Flag : " + str(ip_header_info['Flag_MF']))
        print("\tFragment Offset : " + str(ip_header_info['FragmentOffset']))
        print("\tTTL : " + str(ip_header_info['TTL']))
        print("\tProtocol Number : " + str(ip_header_info['ProtocolNumber']))
        print("\tChecksum : " + str(ip_header_info['Checksum']))
        print("\tSource IP Addr : " + str(ip_header_info['SourceAddr']))
        print("\tDest IP Addr : " + str(ip_header_info['DestAddr']))

        # TODO: Call the appropriate print function based on the ProtocolNumber value
        #  * self.print_TCP_information(print_filter)
        TCPval = 6
        UDPval = 17
        if ip_header_info['ProtocolNumber'] == TCPval:
            self.print_TCP_information(print_filter)
        #  * self.print_UDP_information(print_filter)
        elif ip_header_info['ProtocolNumber'] == UDPval:
            self.print_UDP_information(print_filter)


    def print_ARP_information(self, print_filter='all'):
        print('---- Network Layer Information ----')

        arp_header_info = self.ARPPacketDetails()
        print("\tHardware Type : " + str(arp_header_info['HTYPE']))
        print("\tProtocol Type : " + str(arp_header_info['PTYPE']))
        print("\tHardware Address Len : " + str(arp_header_info['HLEN']))
        print("\tProtocol Address Len : " + str(arp_header_info['PLEN']))
        print("\tOperation : " + str(arp_header_info['OPER']))
        print("\tSender Hardware Address : " + str(arp_header_info['SHA']))
        print("\tSender Protocol Address : " + str(arp_header_info['SPA']))
        print("\tTarget Hardware Address : " + str(arp_header_info['THA']))
        print("\tTarget Protocol Address : " + str(arp_header_info['TPA']))


    def print_IPv6_information(self, print_filter='all'):
        print('---- Network Layer Information ----')
        print("\tIPv6!")


    def print_TCP_information(self, print_filter='all'):
        print('---- Transport Layer Information ----')

        tcp_header_info = self.TCPInfo()
        print("\tTransport Protocol : TCP")
        print("\tSource Port : " + str(tcp_header_info['SourcePort']))
        print("\tDestination Port : " + str(tcp_header_info['DestPort']))
        print("\tSequence Num : " + str(tcp_header_info['SeqNum']))
        print("\tACK Num : " + str(tcp_header_info['ACKNum']))
        print("\tACK Flag : " + str(tcp_header_info['ACK']))
        print("\tRST Flag : " + str(tcp_header_info['RST']))
        print("\tSYN Flag : " + str(tcp_header_info['SYN']))
        print("\tFIN Flag : " + str(tcp_header_info['FIN']))
        print("\tReceive Window : " + str(tcp_header_info['RcvWindow']))
        print("\tChecksum : " + str(tcp_header_info['Checksum']))

        self.print_application_layer_information("TCP", tcp_header_info['SourcePort'], tcp_header_info['DestPort'], print_filter)


    def print_UDP_information(self, print_filter='all'):
        print('---- Transport Layer Information ----')

        udp_header_info = self.UDPInfo()
        print("\tTransport Protocol : UDP")
        print("\tSource Port : " + str(udp_header_info['SourcePort']))
        print("\tDestination Port : " + str(udp_header_info['DestPort']))
        print("\tLength : " + str(udp_header_info['Length']))
        print("\tChecksum : " + str(udp_header_info['Checksum']))

        self.print_application_layer_information("UDP", udp_header_info['SourcePort'], udp_header_info['DestPort'], print_filter)


    def print_application_layer_information(self, transport_protocol, source_port, dest_port, print_filter='all'):
        print('---- Application Layer Information ----')

        #This is a Python dictionary. service_ports [ PortNo ] will give you the corresponding valule.
        #For example, service_ports[22] ---> gives you SSH.
        service_ports = {
            20 : 'File Transfer Protocol (FTP)',            # TCP
            22 : 'Secure Shell (SSH)',                      # TCP
            25 : 'Simple Mail Transfer Protocol (SMTP)',    # TCP (usually)
            53 : 'Domain Name Server (DNS)',                # UDP
            80 : 'HyperText Transfer Protocol (HTTP)'       # TCP
        }

        known_source_port = source_port in service_ports
        known_dest_port = source_port in service_ports

        found_protocol = False
        if known_source_port:
            if transport_protocol == "TCP":
                if source_port == 20:
                    found_protocol = True
                    print("Application protocol: File Transfer Protocol (FTP)")

                elif source_port == 22:
                    found_protocol = True
                    print("Application protocol: Secure Shell (SSH)")

                elif source_port == 25:
                    found_protocol = True
                    print("Application protocol: Simple Mail Transfer Protocol (SMTP)")

                elif source_port == 80:
                    found_protocol = True
                    print("Application protocol: HyperText Transfer Protocol (HTTP)")

            else:
                if source_port == 53:
                    found_protocol = True
                    print("Application protocol: Domain Name Server (DNS)")

        if known_dest_port and not found_protocol:
            if transport_protocol == "TCP":
                if source_port == 20:
                    found_protocol = True
                    print("Application protocol: File Transfer Protocol (FTP)")

                elif source_port == 22:
                    found_protocol = True
                    print("Application protocol: Secure Shell (SSH)")

                elif source_port == 25:
                    found_protocol = True
                    print("Application protocol: Simple Mail Transfer Protocol (SMTP)")

                elif source_port == 80:
                    found_protocol = True
                    print("Application protocol: HyperText Transfer Protocol (HTTP)")

            else:
                if source_port == 53:
                    found_protocol = True
                    print("Application protocol: Domain Name Server (DNS)")

        if not found_protocol:
            print("Application protocol: UNKNOWN")


    def __str__(self):
        return "Packet Size : " + str(self.byte_count) + " Bytes\n" + str(self.packet_representation)


    '''
    takes in a bytes array and returns a formatted string.
    '''
    def format_binary_array(self, arr, byte_sep=' ', group_sep='   '):
        bit_string = ''
        line_length = 32
        group_length = 8

        counter = 0
        for b in arr:
            bit_string = bit_string  + format(b, '02x') + byte_sep

            #Printed one character so far
            counter = counter + 1

            if counter == len(arr): #We are done!
                bit_string = bit_string[:-(len(byte_sep))]
                break
            elif counter % line_length ==0:
                bit_string = bit_string + '\n'
            elif counter % group_length == 0:
                bit_string = bit_string + group_sep

        return bit_string


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--load_packet_log',
                        help='The name of a packet log to load')
    parser.add_argument('--num_packets', type=int,
                        help='The number of packets to capture')
    parser.add_argument('--packet_filter',
                        help='The packet filter setting')
    parser.add_argument('--save_packet_log',
                        help='The packet filter setting')

    args = parser.parse_args()

    sniffer = None
    if args.load_packet_log:
        sniffer = PythonSniffer(packet_log = args.load_packet_log)
    elif args.num_packets:
        sniffer = PythonSniffer(number_of_packets = args.num_packets)
    else:
        sniffer = PythonSniffer(number_of_packets=35)

    print(sniffer)

    packet_filter = 'info'
    if args.packet_filter:
        packet_filter = args.packet_filter

    # Print all the packets
    for p in sniffer.packet_list:
        # str_info = str_info + str(PacketInformation(p))
        PacketInformation(p).print_packet_information(packet_filter)

    if args.save_packet_log:
        sniffer.write_with_pickle(args.save_packet_log)
