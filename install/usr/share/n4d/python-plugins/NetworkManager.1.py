import lliurex.net
import dbus
import yaml

class NetworkManager:
	def __init__(self):
		self.systembus = dbus.SystemBus()
		systemd1 = self.systembus.get_object('org.freedesktop.systemd1','/org/freedesktop/systemd1')
		self.systemdmanager = dbus.Interface(systemd1,'org.freedesktop.systemd1.Manager')
		self.network_file = "/etc/netplan/20-lliurex.yaml"
	#def __init__
	def startup(self,options):
		self.internal_interface = objects['VariablesManager'].get_variable('INTERNAL_INTERFACE')
		self.external_interface = objects['VariablesManager'].get_variable('EXTERNAL_INTERFACE')
	#def startup
	
	def get_interfaces(self):
		return {'status':True,'msg':[x['name'] for x in lliurex.net.get_devices_info()]}
	#def get_interfaces

	def delete_interfaces_in_range(self,range_ip):
		#
		#
		#  Esta funcion la utiliza el zero-server-wizard para limpiar la interfaz virtual, esto se deberia de arraglar de otra forma
		#
		#
	#def delete_interfaces_in_range

	def load_network_file(self):
		
	#def load_network_file
	
	def set_internal_interface(self, interface):
		
	#def set_internal_interfaces

	def set_external_interface(self, interface):
		
	#def set_external_interface

	def interface_dhcp(self, interface, otf):
	
	#def interface_dhcp
			
	def interface_static(self, interface, ip,netmask,otf, gateway=None,dnssearch=None):

	
	#def interface_static
	
	
	def get_info_eth(self,eth):
		if type(eth) == type(""):
			return {'status':True,'msg':lliurex.net.get_device_info(eth)}
		else:
			return {'status':False,'msg':'eth must to be string'}
	#def get_info_eth
	
	def set_nat(self, enable=True, persistent=False , eth=None):
		
		if enabled:
			self.systemdmanager.EnableUnitFiles(['enablenat.service'],not persistent, True)

	#def set_nat
	
	def get_nat(self):


		
	#def get_nat
	
	def set_routing(self, enable=True, persistent=False):
		
	#def set_routing
	
	def get_routing(self):
		
	#def get_routing

	def get_nat_persistence(self):
		
	#def get_nat_persistent

	def get_routing_persistence(self):
		
	#def get_routing_persistent

	def disable_network_manager(self):
		
	#def disable_network_manager
	
	def restart_interfaces(self):
		
	#def restart_interfaces
	
	def backup(self,dir_path="/backup"):

	#def backup
	
	def restore(self,file_path=None):

	#def restore
	
	
if __name__ == '__main__':
	e = NetworkManager()
	
