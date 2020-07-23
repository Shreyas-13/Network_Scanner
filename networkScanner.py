#!/usr/bin/env python
import scapy.all as scapy
import argparse


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_broadcast = broadcast/arp_request
    ans_list = scapy.srp(arp_broadcast, timeout=3)[0]
    clients_list = []
    for i in ans_list:
        dict_info = {"IP": i[1].psrc, "MAC": i[1].hwsrc}
        clients_list.append(dict_info)
    return clients_list


def print_results(array):
    print('IP\t\t\tMAC Address')
    print('-'*40)
    for i in array:
        print(i['IP'] + '\t\t' + i['MAC'])


def get_arguments():
    parser = argparse.ArgumentParser(description='Take argument for IP scan')
    parser.add_argument('--target', '-t', dest='target', help='Specify the IP target or range')
    args = parser.parse_args()
    return args


argument = get_arguments()
results = scan(argument.target)
print_results(results)
