#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import time

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

geoTable = {}
geoIpdb = open("geoipdb.txt")
for line in geoIpdb.readlines():
    startIP, endIP, countryCode = line.split()
    if countryCode not in geoTable.keys():
        geoTable[countryCode] = [(startIP,endIP)]
    else:
        geoTable[countryCode] += [(startIP,endIP)]
geoIpdb.close()

class Firewall:
    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.rules = []
        # TODO: Load the firewall rules (from rule_filename) here.
        self.parseRules(config['rule'])

    def handle_timer(self):
        # TODO: For the timer feature, refer to bypass.py
        print '%s: I am still alive' % time.ctime()
        self.timer.schedule(time.time() + 10.0)

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        # print pkt
        #print pkt_dir
        tcp_src, = struct.unpack('!H', pkt[0:2])
        tcp_dst, = struct.unpack('!H', pkt[2:4])
        ip_headerLen = int(str(int(pkt[0],16) & 0b1111), 16)

        print tcp_src
        print tcp_dst

        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)
        
        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
        else:
            dir_str = 'outgoing'

        pktStuff = self.packetType(pkt,ip_headerLen)
        if pktStuff == None:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_INCOMING:# and self.passPacket(pktStuff,src_ip):
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING and self.passPacket(pktStuff,dst_ip):
            self.iface_ext.send_ip_packet(pkt)


        #print '%s len=%4dB, IPID=%5d  %15s -> %15s' % (dir_str, len(pkt), ipid,
        #        socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_ip))


    def packetType(self, pkt, offset):
        protocol, = struct.unpack('!B', pkt[9])
        packetDict = dict()
        if protocol == 6:
            packetDict = {"ptype":"tcp", "src_port": struct.unpack('!H', pkt[offset:offset+2])[0], "dst_port": struct.unpack('!H', pkt[offset+2:offset+4])[0]}
        elif protocol == 17:
            dst_port = struct.unpack('!H', pkt[offset+2:offset+4])[0]
            src_port = struct.unpack('!H', pkt[offset:offset+2])[0]
            dns = self.isDNS(pkt, offset)
            if dns:
                packetDict = {"ptype":"dns", "hostname":dns}
            else:
                packetDict = {"ptype":"udp", "dst_port":dst_port}

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
                pkt = pkt[offset+12:]
                remainingChars, = struct.unpack('!B',pkt[0])
                domainName = ""
                while remainingChars > 0:
                    domainPart = ""
                    for _ in range(remainingChars):
                        domainPart += struct.unpack('!H',pkt[:2])[0].decode('hex')
                        pkt = pkt[2:]
                    domainName += domainPart + "."
                    remainingChars, = int(struct.unpack('!H',pkt[0]),16)
                domainName = domainName[:-1]

                qType = struct.unpack('!H',pkt[1:3])
                qClass = struct.unpack('!H', pkt[3:5])
                if (qType == 1 or qType == 28) and qClass == 1:
                    return domainName
                return False


    def passPacket(self, packetDict, ip):
        for rule in self.rules:
            hostname = None
            eport = None
            if packetDict.has_key('hostname'):
                hostname = packetDict['hostname']
            if packetDict.has_key('dst_port'):
                eport = packetDict['dst_port']
            print packetDict
            print hostname
            print eport
            currentResult = rule.getPacketResult(packetDict['ptype'], ip, eport, hostname)
            if currentResult != "nomatch":
                result = currentResult
                break
        return result == "pass"
    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
    def parseRules(self, file):
        ruleFile = open(file)
        for line in ruleFile.readlines():
            tokens = line.split()
            #print tokens
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
        if self.packetType == "dns":
            if ("*" not in self.ipAddress) and hostName == self.ipAddress:
                return self.passDrop
            else:
                if len(self.ipAddress) == 1:
                    return self.passDrop
                elif self.ipAddress[1:] == hostName[(len(hostName)-len(self.ipAddress)-1):]:
                    return self.passDrop
                else:
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
                    eportmatch = (self.port == eport)

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
    if geoTable.has_key(countryCode):
        countryCodes = geoTable[countryCode]
        currentChoice = len(countryCode)//2
        lowerBound, upperBound = countryCodes[currentChoice]
        while len(countryCodes) > 0:
            relation = getRelation(currentChoice, lowerBound, upperBound)
            if relation == "<":
                countryCodes = countryCodes[:currentChoice]
                currentChoice = len(countryCodes)//2
            elif relation == ">":
                countryCodes = countryCodes[currentChoice+1:]
                currentChocie = len(countryCodes)//2
            elif relation == "=":
                return True
        return False

    else:
        return False

def getRelation(ipAddress, lowerBound, upperBound):
    ipAddrParts = ipAddress.split(".")
    lowerBoundParts = lowerBound.split(".")
    upperBoundParts = upperBound.split(".")
    for i in range(len(ipAddrParts)):
        if int(ipAddrParts[i]) < int(lowerBoundParts[i]):
            return "<"
        elif int(ipAddrParts[i]) > int(upperBoundsParts[i]):
            return ">"
    return "="
    


