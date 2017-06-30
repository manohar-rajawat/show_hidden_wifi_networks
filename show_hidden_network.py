#!/usr/bin/python 
from scapy.all import *
import time

iface1=raw_input("Enter the interface for put in monitor mode\n")
ap_list=[]

def packethandler(packet):
  for pckt in packet:
    if pckt.haslayer(Dot11):
      if pckt.type==0 and pckt.subtype==8:
        if pckt.info not in ap_list:
          ap_list.append(pckt.info)
          length=pckt[Dot11Beacon].len
          if (length<18):
            pckt.info=pckt.info+'          '
          print "SSID == %s  is on  BSSID == %s" % (pckt.info[0:17],pckt.addr2)
          print '\n'

sniff(iface=iface1,prn=packethandler)
