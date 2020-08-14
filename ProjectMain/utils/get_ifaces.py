# coding=utf-8

from scapy.all import *

def get_ifaces():
    If=ifaces
    Ifaces_data=If.data
    iface_list=list()
    for key in Ifaces_data :
        iface=Ifaces_data.get(key).description
        ip=Ifaces_data.get(key).ip
        mac=Ifaces_data.get(key).mac
        iface_list.append({"iface ":iface,"ip" :ip,"mac":mac})

    return iface_list
