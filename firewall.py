#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import time
import random
import copy

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.
try:
    geoTable = {}
    geoIpdb = open("geoipdb.txt")
    for line in geoIpdb.readlines():
        startIP, endIP, countryCode = line.split()
        if countryCode not in geoTable.keys():
            geoTable[countryCode] = [(startIP,endIP)]
        else:
            geoTable[countryCode] += [(startIP,endIP)]
    geoIpdb.close()
except:
    pass

class Firewall:
    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.rules = []
        self.lossrate = 0
        if config.has_key('rule'):
            self.parseRules(config['rule'])
        if config.has_key('loss'):
            self.lossrate = int(config['loss'])

    def handle_timer(self):
        # print '%s: I am still alive' % time.ctime()
        self.timer.schedule(time.time() + 10.0)

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        #try:
        if self.lossrate == 0 or random.uniform(1,100) > self.lossrate:
            tcp_src, = struct.unpack('!H', pkt[0:2])
            tcp_dst, = struct.unpack('!H', pkt[2:4])

            ip_headerLen = int(str(int(pkt[0],16) & 0b1111), 16)

            src_ip = socket.inet_ntoa(pkt[12:16])
            dst_ip = socket.inet_ntoa(pkt[16:20])
            ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)
            
            if pkt_dir == PKT_DIR_INCOMING:
                dir_str = 'incoming'
            else:
                dir_str = 'outgoing'

            pktStuff = self.packetType(pkt,ip_headerLen)
            print pktStuff
            if pktStuff == None:
                if pkt_dir == PKT_DIR_INCOMING:
                    self.iface_int.send_ip_packet(pkt)
                elif pkt_dir == PKT_DIR_OUTGOING:
                    self.iface_ext.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_INCOMING and self.passPacket(pktStuff,src_ip, pkt, 'incoming'):
                pktStuff['src_ip'] = src_ip
                pktStuff['dst_ip'] = dst_ip
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING and self.passPacket(pktStuff,dst_ip, pkt, 'outgoing'):
                pktStuff['src_ip'] = src_ip
                pktStuff['dst_ip'] = dst_ip
                self.iface_ext.send_ip_packet(pkt)
        #except:
        #    pass


        print '%s len=%4dB, IPID=%5d  %15s -> %15s' % (dir_str, len(pkt), ipid,
               src_ip, dst_ip)


    def packetType(self, pkt, offset):
        protocol, = struct.unpack('!B', pkt[9])
        packetDict = dict()
        if protocol == 6:
            packetDict = {"ptype":"tcp", "src_port": struct.unpack('!H', pkt[offset:offset+2])[0], "dst_port": struct.unpack('!H', pkt[offset+2:offset+4])[0]}
        elif protocol == 17:
            dst_port = struct.unpack('!H', pkt[offset+2:offset+4])[0]
            src_port = struct.unpack('!H', pkt[offset:offset+2])[0]
            dnsResult = self.isDNS(pkt, offset)
            if dnsResult:
                dns,queryID = dnsResult
                packetDict = {"ptype":"dns", "hostname":dns, "dst_port":dst_port, "src_port":src_port, "queryID":queryID}
            else:
                packetDict = {"ptype":"udp", "dst_port":dst_port, "src_port":src_port}

        elif protocol == 1:
            packetDict = {"ptype":"icmp", "type": struct.unpack('!B', pkt[offset])}
        else:
            return None
        return packetDict


    def isDNS(self, pkt, offset):
        dst_port = struct.unpack('!H', pkt[offset+2:offset+4])[0]
        if dst_port != 53:
            return False
        else:
            dnsOffset = offset + 8
            qdcount = struct.unpack('!H', pkt[dnsOffset+4:dnsOffset+6])[0]
            if qdcount != 1:
                return False
            else:
                index = dnsOffset + 12
                remainingChars = struct.unpack('!B',pkt[index])[0]
                domainName = ""
                queryID = pkt[dnsOffset:dnsOffset+2]
                while remainingChars > 0:
                    domainPart = ""
                    for i in range(1,remainingChars+1):
                        intg = struct.unpack('!B',pkt[index+i])[0]
                        domainPart += str(unichr(intg))
                    domainName += domainPart + "."
                    index += remainingChars + 1
                    remainingChars = struct.unpack('!B',pkt[index])[0]
                domainName = domainName[:-1]

                qType = struct.unpack('!H',pkt[index+1:index+3])[0]
                qClass = struct.unpack('!H', pkt[index+3:index+5])[0]
                if (qType == 1 or qType == 28) and qClass == 1:
                    return (domainName, queryID)
                return False


    def passPacket(self, packetDict, ip, pkt, direction):
        for rule in self.rules:
            hostname = None
            eport = None
            if packetDict.has_key('hostname'):
                hostname = packetDict['hostname']
            if packetDict['ptype'] == 'icmp':
                eport = packetDict['type']
            elif direction == 'outgoing' and packetDict.has_key('dst_port'):
                eport = packetDict['dst_port']
            elif direction == 'incoming' and packetDict.has_key('src_port'):
                eport = packetDict['src_port']
            currentResult = rule.getPacketResult(packetDict['ptype'], ip, eport, hostname)
            if currentResult != "nomatch":
                if currentResult == "deny":
                    HOST = ip
                    PORT = eport
                    if packetDict['ptype'] == 'dns':
                        print "denying a dns query"
                        dnsPacket = createDenyDNSResponse(hostName,packetDict['queryID'],packetDict['dst_port'],packetDict['src_port'],packetDict['dst_ip'],packetDict['src_ip'])
                        self.iface_int.send_ip_packet(dnsPacket)

                    if packetDict['ptype'] == 'tcp':
                        print "denying a tcp packet"
                        rst_pkt = makeRSTpacket(pkt)
                        self.iface_int.send_ip_packet(rst_pkt)
                    return False
                else:
                    return currentResult == "pass" #result = currentResult
        return True

    def makeRSTpacket(self, pkt):

        # I did this to make a deep copy of the packet and cut off unnecessary options and tcp data. 
        # Not sure if it should be done this way.
        ip_len = int(str(int(pkt[0],16) & 0b1111), 16)
        rst_pkt = pkt[:ip_len+20]

        # -------------------------------
        # fix the ip header and checksum
        # -------------------------------
        
        # swap the src and dst ips
        rst_pkt[12:16] = pkt[16:20]
        rst_pkt[16:20] = pkt[12:16]

        # set checksum = 0x0000
        rst_pkt[10:12] = struct.pack('!H',0x0000)

        # calculate ipchecksum
        rst_pkt[10:12] = struct.pack('!H', self.ip_checksum(rst_pkt))

        # ---------------------------------
        # fix the tcp header and checksum
        # ---------------------------------

        # swap the TCP ports
        rst_pkt[ip_len : ip_len+2] = pkt[ip_len+2 : ip_len+4]
        rst_pkt[ip_len + 2 : ip_len + 4] = pkt[ip_len : ip_len + 2]
        
        # change TCP ack number
        rst_pkt[ip_len+8 : ip_len+12] = struct.pack('!L', struct.unpack('!L', pkt[ip_len+4 : ip_len+8])[0] + 1)

        # set the flag to RST
        rst_pkt[ip_len+13] = struct.pack('!B', 0x04)

        # TCP checksum = 0x0000
        rst_pkt[ip_len+16:ip_len+18] = struct.pack('!H', 0x0000)

        # set the offset to 5
        rst_pkt[ip_len+12] = struct.pack('!B', 0x50)

        # calculate tcp_checksum
        rst_pkt[ip_len+16:ip_len+18] = struct.pack('!H', tcp_checksum(rst_pkt))

        return rst_pkt

    def ip_checksum(self, pkt):
        headerlen = int(str(int(pkt[0],16) & 0b1111), 16)
        total = 0
        counter = 0
        while(counter < headerlen):
            total += struct.unpack('!H', pkt[counter:counter+2])[0]
            counter += 2
        total = (total >> 16) + (total & 0xFFFF)
        total += (total >> 16)
        total = total ^ 0xFFFF
        return total

    def tcp_checksum(self, pkt):
        w = int(str(int(pkt[0],16) & 0b1111), 16)
        ip_src = struct.unpack('!L', pkt[12:16])
        ip_dst = struct.unpack('!L', pkt[16:20])

        tcp_prot = 6
        bitsleft = 20

        total = 0

        while bitsleft > 1:
            total += struct.unpack('!H', pkt[w:w+2])[0]
            w += 2
            bitsleft -= 2
        if bitsleft > 0:
            total += struct.unpack('!B', pkt[w])[0]

        # add pseudo header
        total += struct.unpack('!L', src_addr)[0]
        total += struct.unpack('!L', dest_addr)[0]
        total += 20
        total += tcp_protocol

        total = (total >> 16) + (total & 0xFFFF)
        total += (total >> 16)

        total = total ^ 0xFFFF

        return total


    def createDenyDNSResponse(hostName, packetID, sourcePort, destPort, sourceIP, destIP):
        #DNS QUERY RESPONSE STUFF
        packet = ""
        hostInfo = []
        for part in hostName.split('.'):
            packString += 'b' + str(len(part)) + 's'
            hostInfo += [len(part)]
            hostInfo += [part]
        hostInfo += [0]
        packString += 'b'
        host = struct.pack(*([packString]+hostInfo))
        flags = struct.pack('H',33152)
        questions = struct.pack('!H',1)
        ancount = struct.pack('!H',1)
        nsCount = struct.pack('H',0)
        arCount = struct.pack('H',0)
        queryType = struct.pack('!H',1)
        queryClass = struct.pack('!H', 1)
        nameAndPointer = struct.pack('!H',int('c00c',16))
        TTL = struct.pack('!l', 1)
        dataLength = struct.pack('!H',4)
        address = socket.inet_aton('169.229.49.109')
        dnsPacket = packetID+flags+questions+ancount+nsCount+arCount+\
            nsCount+arCount+host+queryType+queryClass+nameAndPointer+\
            queryType+queryClass+TTL+dataLength+address

        #UDP HEADER STUFF
        sourcePort = struct.pack('!H',sourcePort)
        destPort = struct.pack('!H',destPort)
        dnsLength = len(dnsPacket)
        checksum = struct.pack('!H', 0)
        udpPacket = sourcePort + destPort + dnsLength + checksum + dnsPacket

        #IP HEADER STUFF
        version = struct.pack('!B',int('45',16))
        DSCPECN = struct.pack('!B',0)
        packetLength = struct.pack('!H', 20+len(udpPacket))
        identification = struct.pack('!H', 0)
        #flags = struct.pack('!B', 0)
        flagsAndFragmentOffset = struct.pack('!H', 0)
        IPTTL = struct.pack('!B', 1)
        protocol = struct.pack('!B',17) # 17 = UDP
        ipChecksum = struct.pack('!H',0) #temporarily zero until we calculate it
        ipHeader = version+DSCPECN+packetLength+identification+flags+fragmentOffset+flagsAndFragmentOffset+IPTTL+protocol+ipChecksum+sourceIP+destIP
        ipChecksum = struct.pack('!H',ip_checksum(ipHeader))

        ipHeader = version+DSCPECN+packetLength+identification+flags+fragmentOffset+flags+fragmentOffset+IPTTL+protocol+ipChecksum+sourceIP+destIP
        packet = ipHeader + udpPacket

        return packet

# TODO: You may want to add more classes/functions as well.
    def parseRules(self, file):
        ruleFile = open(file)
        for line in ruleFile.readlines():
            tokens = line.split()
            if len(tokens) == 0:
                pass
            elif tokens[0] == "%":
                continue
            elif len(tokens) == 3:
                self.rules.append(Rule(tokens[0], tokens[1], tokens[2]))
            else:
                self.rules.append(Rule(tokens[0], tokens[1], tokens[2], tokens[3]))
        ruleFile.close()
        self.rules.reverse()

class Rule:

    def __init__(self, passDrop, packetType, ipAddress, port = 0):
        self.passDrop = passDrop
        self.packetType = packetType
        self.ipAddress = ipAddress
        self.port = port


    def getPacketResult(self, ptype, addr, eport, hostName):
        if ptype == "dns":
            if ("*" not in self.ipAddress) and hostName == self.ipAddress:
                return self.passDrop
            elif "*" in self.ipAddress:
                if len(self.ipAddress) == 1:
                    return self.passDrop
                elif self.ipAddress[1:] == hostName[-len(self.ipAddress[1:]):]:
                    return self.passDrop
                else:
                    return "nomatch"
            else:
                #If the packet is a dns packet, it should respond to udp rules
                if self.packetType == "udp":
                    eipmatch = False
                    eportmatch = False
                    # external ip addr matching
                    if self.ipAddress == "any":
                        eipmatch = True
                    elif len(self.ipAddress) == 2 and isInCountry(self.ipAddress, addr):
                        eipmatch = True
                    elif "/" in self.ipAddress:
                        ipAddr = self.ipAddress.split("/")[0]
                        prefix = self.ipAddress.split("/")[1]
                        eipmatch = self.prefixMask(addr, ipAddr, prefix)
                    else:
                        eipmatch = (addr == self.ipAddress)

                    # external port matching
                    if self.port == "any":
                        eportmatch = True
                    elif "-" in self.port:
                        r = self.port.split("-")
                        eportmatch = eport in range(int(r[0]),int(r[1])+1)
                    else:
                        eportmatch = (int(self.port) == eport)

                    # 
                    if eipmatch and eportmatch:
                        return self.passDrop
                    return "nomatch"
                    
                return "nomatch"
        else: # protocols
            if ptype == self.packetType:

                eipmatch = False
                eportmatch = False

                # external ip addr matching
                if self.ipAddress == "any":
                    eipmatch = True
                elif len(self.ipAddress) == 2 and isInCountry(self.ipAddress, addr):
                    eipmatch = True
                elif "/" in self.ipAddress:
                    ipAddr = self.ipAddress.split("/")[0]
                    prefix = self.ipAddress.split("/")[1]
                    eipmatch = self.prefixMask(addr, ipAddr, prefix)
                else:
                    eipmatch = (addr == self.ipAddress)

                # external port matching
                if self.port == "any":
                    eportmatch = True
                elif "-" in self.port:
                    r = self.port.split("-")
                    eportmatch = eport in range(int(r[0]),int(r[1])+1)
                else:
                    eportmatch = (int(self.port) == eport)

                # 
                if eipmatch and eportmatch:
                    return self.passDrop
                else:
                    return "nomatch"

            else:
                return "nomatch"

    def prefixMask(self, addr, addrToMatch, prefix):
        toMatchList = addrToMatch.split(".")
        numList = addr.split(".")
        numToMatch = 0
        num = 0
        for i in range(4):
            numToMatch = numToMatch << 8
            numToMatch += int(toMatchList[i])

            num = num << 8
            num += int(numList[i])

        mask = 32 - prefix
        num = num >> mask
        numToMatch = numToMatch >> mask
        return num == numToMatch  
        
        
def isInCountry(countryCode, ipAddress):
    countryCode = countryCode.upper()
    if geoTable.has_key(countryCode):
        for lowerBound,upperBound in geoTable[countryCode]:
            if getRelation(ipAddress,lowerBound,upperBound) == "=":
                return True
    return False


def getRelation(ipAddress, lowerBound, upperBound):
    ipAddrParts = ipAddress.split(".")
    lowerBoundParts = lowerBound.split(".")
    upperBoundParts = upperBound.split(".")
    for i in range(len(ipAddrParts)):
        if int(ipAddrParts[i]) < int(lowerBoundParts[i]):
            return "<"
        elif int(ipAddrParts[i]) > int(upperBoundParts[i]):
            return ">"
    return "="