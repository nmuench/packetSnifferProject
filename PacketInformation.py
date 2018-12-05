import datetime
import sys
import argparse
import socket
from struct import *
from PythonSniffer import PythonSniffer
from enum import Enum


class PacketInformation:

    #The packet is passed from the PythonSniffer and processed in different format for your convenience.
    def __init__(self, bytes_tuple_info, extra_credit):
        self.bytes_tuple_info = bytes_tuple_info
        self.packet_byte_array = bytes_tuple_info[0]
        self.packet_representation = dict()
        self.EC = extra_credit

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
        etherStart = 0
        etherSize = 14
        etherEnd = etherStart + etherSize
        # TODO: Complete this function by extracting the ethernet header and assigning
        # TODO: the values created in the above dictionary
        ethernetInfo = unpack('!6s6sH', self.bytes_tuple_info[0][etherStart:etherEnd])

        eth_details['DestMAC'] = self.macify(ethernetInfo[0])
        eth_details['SourceMAC'] = self.macify(ethernetInfo[1])
        eth_details['EtherType'] = self.hexify(ethernetInfo[2])

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

        # Extract the protocol information, no processing
        ip_details['Checksum'] = iph[7]

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
        arpStart = 14
        arpSize = 28
        arpEnd = arpStart + arpSize
        # TODO: Complete this function by extracting the ARP header and assigning
        # the values created in the above dictionary
        arpInfo = unpack('!HHBBH6s4s6s4s', self.packet_byte_array[arpStart:arpEnd])
        arp_details['HTYPE'] = arpInfo[0]
        arp_details['PTYPE'] = self.hexify(arpInfo[1])
        arp_details['HLEN'] = arpInfo[2]
        arp_details['PLEN'] = arpInfo[3]
        arp_details['OPER'] = arpInfo[4]
        arp_details['SHA'] = self.macify(arpInfo[5])
        arp_details['SPA'] = socket.inet_ntoa(arpInfo[6])
        arp_details['THA'] = self.macify(arpInfo[7])
        arp_details['TPA'] = socket.inet_ntoa(arpInfo[8])

        return arp_details

    ####################################################################################################################
    ####################################################################################################################
    ### Transport Layer Processing
    ### You need to process the following Transport Layer segments. You can determine what type of Transport Layer segment
    ### is in a packet using IPv4's Protocol field
    ### 1. IPv4
    ### 2. ARP

    '''
    If packet is a TCP packet, get some information on it. For simplicity, I only want the source port and destination port since these are very useful.
    For example, a port number of 443 indicate this is a secure HTTP packet (HTTPs)
    '''
    def TCPInfo(self):
        tcp_details = {
            'SourcePort' : None,
            'DestPort' : None,
            'SeqNum' : None,
            'ACKNum' : None,
            'DataOffset' : None,
            'ACK' : None,
            'RST' : None,
            'SYN' : None,
            'FIN' : None,
            'RcvWindow' : None,
            'Checksum' : None
        }

        # TODO: Complete this function by extracting the TCP header and assigning
        # the values created in the above dictionary. Note that ACK, RST, SYN, and FIN are 1 bit flags
        tcpStart = 34
        tcpSize = 20
        tcpEnd = tcpStart + tcpSize
        tcpInfo = unpack('!HHIIBBHHH', self.packet_byte_array[tcpStart:tcpEnd])
        tcp_details['SourcePort'] = tcpInfo[0]
        tcp_details['DestPort'] = tcpInfo[1]
        tcp_details['SeqNum'] = tcpInfo[2]
        tcp_details['ACKNum'] = tcpInfo[3]
        tcp_details['DataOffset'] = tcpInfo[4] >> 4
        tcp_details['ACK'] = (tcpInfo[5] >> 4) & 1
        tcp_details['RST'] = (tcpInfo[5] >> 2) & 1
        tcp_details['SYN'] = (tcpInfo[5] >> 1) & 1
        tcp_details['FIN'] = tcpInfo[5] & 1
        tcp_details['RcvWindow'] = tcpInfo[6]
        tcp_details['Checksum'] = tcpInfo[7]
        return tcp_details

    '''
    If packet is a UDP packet, get some information on it. For simplicity, I only want the source port and destination port since these are very useful.
    For example, a port number of 53 indicate this is a DNS query
    '''
    def UDPInfo(self):
        udp_details = {
            'SourcePort': None,
            'DestPort': None,
            'Length': None,
            'Checksum': None
        }

        # TODO: Complete this function by extracting the UDP header and assigning
        # the values created in the above dictionary.
        udpStart = 34
        udpSize = 8
        udpEnd = udpStart + udpSize
        udpInfo = unpack('!HHHH', self.packet_byte_array[udpStart:udpEnd])
        udp_details['SourcePort'] = udpInfo[0]
        udp_details['DestPort'] = udpInfo[1]
        #udp_details['Length'] = udpInfo[2]
        #udp_details['Checksum'] = udpInfo[3]
        return udp_details


    '''
    EXTRA CREDIT: If this is an HTTP message, extract the content of the HTTP message
    Extract the header and the body and convert it into a human-readable format.
    Return the human-readable result. You do NOT need to split the message into its
    components (e.g. header + body, or different parts of the header)

    transport_layer_offset contains (header length / 4), based on TCP's Data Offset field
    '''
    def HTTPInfo(self, transport_layer_offset):
        pass

    '''
    EXTRA CREDIT: If this is an DNS message, extract the fields from the DNS header
    that are included in the dictionary in the function below.

    transport_layer_offset contains (header length / 4), based on TCP's Data Offset field
    '''
    def DNSInfo(self, transport_layer_offset):
        pass
        dns_details = {
            'MessageID': None,
            'QuestionCount': None,
            'AnswerCount': None,
            'AuthorityCount': None,
            'AdditionalCount': None
        }

        #return dns_details

    ####################################################################################################################
    ####################################################################################################################
    ### Printing the contents of the sniffed packets

    def print_packet_information(self, print_filter='all'):

        # Printing Packets Content in Hexadecimal Format
        if print_filter == 'all':
            print("Interface : " + self.bytes_tuple_info[1][0], end='\r\n')
            print(self.format_binary_array(self.bytes_tuple_info[1][4]), end='\r\n')
            print(self.format_binary_array(self.packet_byte_array), end='\r\n')

        print("=========== PACKET ===========", end='\r\n')
        print("Size : " + str(len(self.packet_byte_array)) + " Bytes", end='\r\n')

        return self.print_ethernet_information(packet_filter)


    def print_ethernet_information(self, print_filter='all'):
        print('---- Link Layer Information ----', end='\r\n')

        try:
            eth_result = self.EthernetDetails()
            print("\tDestination MAC: " + eth_result["DestMAC"], end='\r\n')
            print("\tSource MAC: " + eth_result["SourceMAC"], end='\r\n')
            print("\tEtherType: " + eth_result["EtherType"], end='\r\n')

            ip4Val = '0x0800'
            ip6Val = '0x86DD'
            arpVal = '0x0806'
            # TODO: Call the appropriate print function based on the EtherType value
            #  * self.print_IPv4_information(print_filter)
            #  * self.print_ARP_information(print_filter)
            #  * self.print_IPv6_information(print_filter)
            if eth_result['EtherType'] == ip4Val:
                return self.print_IPv4_information(print_filter)
            #  * self.print_ARP_information(print_filter)
            elif eth_result['EtherType'] == arpVal:
                return self.print_ARP_information(print_filter)
            #  * self.print_IPv6_information(print_filter)
            elif eth_result['EtherType'] == ip6Val:
                return self.print_IPv6_information(print_filter)

            return False, "UNKNOWN"
        except:
            return False, "ERROR"



    # Check the IP header protocol field is 6, the packet is TCP. 17 is for UDP and 1 is for ICMP.
    # For UDP and TCP headers (which follow the IP header) get the source & destination port number and store them in this list.
    def print_IPv4_information(self, print_filter='all'):
        print('---- Network Layer Information ----', end='\r\n')

        try:
            ip_header_info = self.IPPacketDetails()
            print("\tIP Version : " + str(ip_header_info['IPVersion']), end='\r\n')
            print("\tHeader Length : " + str(ip_header_info['IHL']), end='\r\n')
            print("\tData Length : " + str(ip_header_info['Length']), end='\r\n')
            print("\tFragment ID: " + str(ip_header_info['Identifier']), end='\r\n')
            print("\tDon't Fragment Flag : " + str(ip_header_info['Flag_DF']), end='\r\n')
            print("\tMore Fragments Flag : " + str(ip_header_info['Flag_MF']), end='\r\n')
            print("\tFragment Offset : " + str(ip_header_info['FragmentOffset']), end='\r\n')
            print("\tTTL : " + str(ip_header_info['TTL']), end='\r\n')
            print("\tProtocol Number : " + str(ip_header_info['ProtocolNumber']), end='\r\n')
            print("\tChecksum : " + str(ip_header_info['Checksum']), end='\r\n')
            print("\tSource IP Addr : " + str(ip_header_info['SourceAddr']), end='\r\n')
            print("\tDest IP Addr : " + str(ip_header_info['DestAddr']), end='\r\n')

            # TODO: Call the appropriate print function based on the ProtocolNumber value
            #  * self.print_TCP_information(print_filter)
            #  * self.print_UDP_information(print_filter)
            TCPval = 6
            UDPval = 17
            if ip_header_info['ProtocolNumber'] == TCPval:
                return self.print_TCP_information(print_filter)
            #  * self.print_UDP_information(print_filter)
            elif ip_header_info['ProtocolNumber'] == UDPval:
                return self.print_UDP_information(print_filter)
            return False, "UNKNOWN"
        except:
            return False, "ERROR"


    def print_ARP_information(self, print_filter='all'):
        print('---- Network Layer Information ----', end='\r\n')

        try:
            arp_header_info = self.ARPPacketDetails()
            print("\tHardware Type : " + str(arp_header_info['HTYPE']), end='\r\n')
            print("\tProtocol Type : " + str(arp_header_info['PTYPE']), end='\r\n')
            print("\tHardware Address Len : " + str(arp_header_info['HLEN']), end='\r\n')
            print("\tProtocol Address Len : " + str(arp_header_info['PLEN']), end='\r\n')
            print("\tOperation : " + str(arp_header_info['OPER']), end='\r\n')
            print("\tSender Hardware Address : " + str(arp_header_info['SHA']), end='\r\n')
            print("\tSender Protocol Address : " + str(arp_header_info['SPA']), end='\r\n')
            print("\tTarget Hardware Address : " + str(arp_header_info['THA']), end='\r\n')
            print("\tTarget Protocol Address : " + str(arp_header_info['TPA']), end='\r\n')

            return True, "ARP"
        except:
            return False, "ERROR"


    def print_IPv6_information(self, print_filter='all'):
        print('---- Network Layer Information ----', end='\r\n')

        try:
            print("\tIPv6!", end='\r\n')
            return True, "IPv6"

        except:
            return False, "ERROR"


    def print_TCP_information(self, print_filter='all'):
        print('---- Transport Layer Information ----', end='\r\n')

        try:
            tcp_header_info = self.TCPInfo()
            print("\tTransport Protocol : TCP", end='\r\n')
            print("\tSource Port : " + str(tcp_header_info['SourcePort']), end='\r\n')
            print("\tDestination Port : " + str(tcp_header_info['DestPort']), end='\r\n')
            print("\tSequence Num : " + str(tcp_header_info['SeqNum']), end='\r\n')
            print("\tData Offset : " + str(tcp_header_info['DataOffset']), end='\r\n')
            print("\tACK Num : " + str(tcp_header_info['ACKNum']), end='\r\n')
            print("\tACK Flag : " + str(tcp_header_info['ACK']), end='\r\n')
            print("\tRST Flag : " + str(tcp_header_info['RST']), end='\r\n')
            print("\tSYN Flag : " + str(tcp_header_info['SYN']), end='\r\n')
            print("\tFIN Flag : " + str(tcp_header_info['FIN']), end='\r\n')
            print("\tReceive Window : " + str(tcp_header_info['RcvWindow']), end='\r\n')
            print("\tChecksum : " + str(tcp_header_info['Checksum']), end='\r\n')

            return self.print_application_layer_information("TCP",
                                                            tcp_header_info['DataOffset'],
                                                            tcp_header_info['SourcePort'],
                                                            tcp_header_info['DestPort'],
                                                            print_filter)
        except:
            return False, "ERROR"


    def print_UDP_information(self, print_filter='all'):
        print('---- Transport Layer Information ----', end='\r\n')

        try:
            udp_header_info = self.UDPInfo()
            print("\tTransport Protocol : UDP", end='\r\n')
            print("\tSource Port : " + str(udp_header_info['SourcePort']), end='\r\n')
            print("\tDestination Port : " + str(udp_header_info['DestPort']), end='\r\n')
            print("\tLength : " + str(udp_header_info['Length']), end='\r\n')
            print("\tChecksum : " + str(udp_header_info['Checksum']), end='\r\n')

            return self.print_application_layer_information("UDP",
                                                            2,
                                                            udp_header_info['SourcePort'],
                                                            udp_header_info['DestPort'], print_filter)
        except:
            return False, "ERROR"


    def print_application_layer_information(self, transport_protocol, transport_layer_offset, source_port, dest_port, print_filter='all'):
        print('---- Application Layer Information ----', end='\r\n')

        # This is a Python dictionary. service_ports [ PortNo ] will give you the corresponding valule.
        # For example, service_ports[22] ---> gives you SSH.
        service_ports = {
            # 20: 'File Transfer Protocol (FTP)',  # TCP
            # 22: 'Secure Shell (SSH)',  # TCP
            # 25: 'Simple Mail Transfer Protocol (SMTP)',  # TCP (usually)
            53: 'Domain Name Server (DNS)',  # UDP
            80: 'HyperText Transfer Protocol (HTTP)'  # TCP
        }

        try:
            known_source_port = source_port in service_ports
            known_dest_port = dest_port in service_ports

            found_protocol = False
            if known_source_port:
                if transport_protocol == "TCP":
                    if source_port == 20:
                        found_protocol = True
                        print("Application protocol: File Transfer Protocol (FTP)", end='\r\n')
                        return True, "FTP"

                    elif source_port == 22:
                        found_protocol = True
                        print("Application protocol: Secure Shell (SSH)", end='\r\n')
                        return True, "SSH"

                    elif source_port == 25:
                        found_protocol = True
                        print("Application protocol: Simple Mail Transfer Protocol (SMTP)", end='\r\n')
                        return True, "SMTP"

                    elif source_port == 80:
                        found_protocol = True
                        print("Application protocol: HyperText Transfer Protocol (HTTP)", end='\r\n')

                        if self.EC:
                            http_header_info = self.HTTPInfo(transport_layer_offset)
                            print(http_header_info)

                        return True, "HTTP"

                else:
                    if source_port == 53:
                        found_protocol = True
                        print("Application protocol: Domain Name Server (DNS)", end='\r\n')

                        if self.EC:
                            dns_details = self.DNSInfo(transport_layer_offset)
                            print("\tMessage ID : " + str(dns_details['MessageID']), end='\r\n')
                            print("\tQuestion Count : " + str(dns_details['QuestionCount']), end='\r\n')
                            print("\tAnswer Count : " + str(dns_details['AnswerCount']), end='\r\n')
                            print("\tAuthority Count : " + str(dns_details['AuthorityCount']), end='\r\n')
                            print("\t Additional Count : " + str(dns_details['AdditionalCount']), end='\r\n')

                        return True, "DNS"

            if known_dest_port and not found_protocol:
                if transport_protocol == "TCP":
                    if dest_port == 20:
                        found_protocol = True
                        print("Application protocol: File Transfer Protocol (FTP)", end='\r\n')
                        return True, "FTP"

                    elif dest_port == 22:
                        found_protocol = True
                        print("Application protocol: Secure Shell (SSH)", end='\r\n')
                        return True, "SSH"

                    elif dest_port == 25:
                        found_protocol = True
                        print("Application protocol: Simple Mail Transfer Protocol (SMTP)", end='\r\n')
                        return True, "SMTP"

                    elif dest_port == 80:
                        found_protocol = True
                        print("Application protocol: HyperText Transfer Protocol (HTTP)", end='\r\n')

                        if self.EC:
                            http_header_info = self.HTTPInfo(transport_layer_offset)
                            print(http_header_info, end='\r\n')

                        return True, "HTTP"

                else:
                    if dest_port == 53:
                        found_protocol = True
                        print("Application protocol: Domain Name Server (DNS)", end='\r\n')

                        if self.EC:
                            dns_details = self.DNSInfo(transport_layer_offset)
                            print("\tMessage ID : " + str(dns_details['MessageID']), end='\r\n')
                            print("\tQuestion Count : " + str(dns_details['QuestionCount']), end='\r\n')
                            print("\tAnswer Count : " + str(dns_details['AnswerCount']), end='\r\n')
                            print("\tAuthority Count : " + str(dns_details['AuthorityCount']), end='\r\n')
                            print("\tAdditional Count : " + str(dns_details['AdditionalCount']), end='\r\n')

                        return True, "DNS"

            if not found_protocol:
                print("Application protocol: UNKNOWN", end='\r\n')
                return False, "UNKNOWN"

        except Exception as err:
            return False, "ERROR"


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


class LinkLayerProtocols(Enum):
    Ethernet = 1


class NetworkLayerProtocols(Enum):
    IPv4 = 1,
    ARP = 2


class TransportLayerProtocols(Enum):
    TCP = 1,
    UDP = 2


class ApplicationLayerProtocols(Enum):
    TCP = 1,
    UDP = 2


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
    parser.add_argument('--ignore_unrecognized_packets', type=bool,
                        help='The packet filter setting')
    parser.add_argument('--extra_credit', type=bool,
                        help='The packet filter setting')
    args = parser.parse_args()

    ec = False
    if args.extra_credit:
        ec = True

    sniffer = None
    if args.load_packet_log:
        sniffer = PythonSniffer(packet_log=args.load_packet_log)
    elif args.num_packets:
        sniffer = PythonSniffer(number_of_packets=args.num_packets)
    else:
        sniffer = PythonSniffer(number_of_packets=0)

    print(sniffer, end='\r\n')

    packet_filter = 'info'
    if args.packet_filter:
        packet_filter = args.packet_filter

    pkt_types = {
        "ARP": 0,  # TCP
        "IPv6": 0,  # TCP
        "HTTP": 0,  # TCP
        "DNS": 0,  # UDP
        "UNKNOWN": 0,
        "ERROR": 0
    }

    # Print all the packets
    for p in sniffer.packet_list:
        # str_info = str_info + str(PacketInformation(p))
        res, type = PacketInformation(p, ec).print_packet_information(packet_filter)
        pkt_types[type] += 1

        if (not args.ignore_unrecognized_packets) or res:
            sniffer.good_packet_list.append(p)
    print(end='\r\n')
    print(' =====================================================', end='\r\n')
    print('\tFound', pkt_types['ARP'],'ARP packets', end='\r\n')
    print('\tFound', pkt_types['IPv6'],'IPv6 packets', end='\r\n')
    print('\tFound', pkt_types['HTTP'],'HTTP packets', end='\r\n')
    print('\tFound', pkt_types['DNS'],'DNS packets', end='\r\n')
    print('\tFound', pkt_types['UNKNOWN'],'UNKNOWN packets', end='\r\n')
    print('\tFound', pkt_types['ERROR'],'ERROR packets', end='\r\n')

    if args.save_packet_log:
        sniffer.write_with_pickle(args.save_packet_log)
