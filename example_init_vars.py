#!/usr/bin/python
import xmlrpclib

ip_server = '10.0.0.195'
c = xmlrpclib.ServerProxy("https://"+ip_server+":9779")
#c = xmlrpclib.ServerProxy("https://192.168.1.2:9779")
user = ("lliurex","lliurex")

#print c.get_methods('SambaManager')
print c.set_internal_interface(user,'NetworkManager','eth0')
#print c.set_external_interface(user,'NetworkManager','eth1')
#print c.interface_static(user,'NetworkManager','eth0','10.2.1.254','255.255.255.0')
#print c.interface_dhcp(user,'NetworkManager','eth1')
#print c.restart_interfaces(user,'NetworkManager')
#restore : adm admins
#print c.init_network_vars(user,'NetworkManager')
#test : * anonymous 
#backup : adm admins
