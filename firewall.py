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
        print pkt
        print pkt_dir
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)
        
        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
        else:
            dir_str = 'outgoing'

        print '%s len=%4dB, IPID=%5d  %15s -> %15s' % (dir_str, len(pkt), ipid,
                socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_ip))

        # ... and simply allow the packet.
        if pkt_dir == PKT_DIR_INCOMING:# and self.passPacket(passDrop, packetType, ipAddress, port):
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:# and self.passPacket(passDrop, packetType, ipAddress, port):
            self.iface_ext.send_ip_packet(pkt)
        import sys
        sys.exit()

    def passPacket(self, passDrop, packetType, ipAddress, port):
        result = "pass"
        for rule in self.rules:
            currentResult = rule.getPacketResult(passDrop, packetType, ipAddress, port)
            if currentResult != "nomatch":
                result = currentResult
        return result == "pass"
    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
    def parseRules(self, file):
        ruleFile = open(file)
        for line in ruleFile.readlines():
            tokens = line.split()
            print tokens
            if len(tokens) == 0:
                pass
            elif tokens[0] == "%":
                continue
            elif len(tokens) == 3:
                self.rules.append(Rule(tokens[0], tokens[1], tokens[2]))
            else:
                self.rules.append(Rule(tokens[0], tokens[1], tokens[2], tokens[3]))
        ruleFile.close()

class Rule:

    def __init__(self, passDrop, packetType, ipAddress, port = 0):
        self.passDrop = passDrop
        self.packetType = packetType
        self.ipAddress = ipAddress
        self.port = port

    def getPacketResult(self, ptype, addr, eport, hostName):
        if packetType == "dns":
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
                    eportmatch = eport in range(int(r[0]),int(r[1]))
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
    


