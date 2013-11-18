#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import socket
import struct
import time

class Firewall:
    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        #self.logfile = open("log.txt", "w+")
        #self.logfile.write("Packet Length, Direction, ipid, src_ip, dst_ip")

        print 'bypass mode!'

        # Schedule for the initial timer event
        self.timer.schedule(time.time() + 10.0)

    def handle_timer(self):
        # Print the message every 10 seconds
        print '%s: I am still alive' % time.ctime()
        self.timer.schedule(time.time() + 10.0)
        
    def handle_packet(self, pkt_dir, pkt):
        # The example code here prints out the source/destination IP addresses,
        # which is unnecessary for your submission.
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)
        
        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
        else:
            dir_str = 'outgoing'

        print '%s len=%4dB, IPID=%5d  %15s -> %15s' % (dir_str, len(pkt), ipid,
                socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_ip))
        #self.logfile.write(str(len(pkt))+","+dir_str+","+str(ipid)+","+socket.inet_ntoa(src_ip)+","+socket.inet_ntoa(dst_ip)+"\n")
        #self.logfile.flush()

        # ... and simply allow the packet.
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)
