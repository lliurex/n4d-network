import lliurex.net
import lliurex.interfacesparser
import subprocess
import os
import tempfile
import shutil
import time
import tarfile
class NetworkManager:
	def __init__(self):
		self.path_interfaces = '/etc/network/interfaces'
		self.interfaces = lliurex.interfacesparser.InterfacesParser()
		self.interfaces.load(self.path_interfaces)
		self.backup_files=["/etc/network/interfaces", "/etc/init/network-manager.override"]
		self.rules_file="/etc/udev/rules.d/70-persistent-net.rules"
		
		
	#def __init__
	def startup(self,options):
		self.internal_interface = objects['VariablesManager'].get_variable('INTERNAL_INTERFACE')
		self.external_interface = objects['VariablesManager'].get_variable('EXTERNAL_INTERFACE')
	#def startup
	
	def get_interfaces(self):
		return {'status':True,'msg':[x['name'] for x in lliurex.net.get_devices_info()]}
	#def get_interfaces
	
	def get_interfaces_network_file(self):
		return {'status':True,'msg':self.interfaces.get_list_interfaces()}
	#def get_interfaces_network_file

	def delete_interfaces_in_range(self,range_ip):

		for iface in self.interfaces.get_interfaces_in_range(range_ip):
			self.interfaces.delete_all_interface(iface)

		return {'status':True,'msg':'Old replication interfaces removed'}

	#def delete_interfaces_in_range

	def load_network_file(self):
		try:
			self.interfaces.load('/etc/network/interfaces')
		except Exception as e:
			if "not exists" in e.message :
				return {'status':False,'msg':'File not exist'}
		
		return {'status':True,'msg':'Reload file'}
	#def load_network_file
	
	def set_internal_interface(self, interface):
		objects['VariablesManager'].init_variable('INTERNAL_INTERFACE',{'internal_interface':interface})
		self.internal_interface = interface
		
		ip = None
		netmask = None
		listinfo = self.interfaces.get_info_interface(interface)
		for stanza in listinfo:
			if(stanza.__class__.__name__ == 'StanzaIface'):
				if (stanza.method == 'static' ):
					for option in stanza.options:
						if (option.startswith('address')):
							try:
								ip = option.split(" ")[1]
							except Exception as e:
								pass
						if (option.startswith('netmask')):
							try:
								netmask = option.split(" ")[1]
							except Exception as e:
								pass
		if(ip == None):
			ip = lliurex.net.get_ip(interface)
		if(netmask == None):
			netmask = lliurex.net.get_netmask(interface)
			
		if (ip != None and netmask != None):
			objects['VariablesManager'].init_variable('INTERNAL_NETWORK',{'ip':ip,'netmask':netmask})
			objects['VariablesManager'].init_variable('INTERNAL_MASK',{'internal_mask':netmask})
			objects['VariablesManager'].init_variable('SRV_IP',{'ip':ip})
		return {'status':True,'msg':'internal interface'}
	#def set_internal_interfaces

	def set_external_interface(self, interface):
		objects['VariablesManager'].init_variable('EXTERNAL_INTERFACE',{'external_interface':interface})
		self.external_interface = interface
		return {'status':True,'msg':'external interface'}
	#def set_external_interface

	def interface_dhcp(self, interface, otf):
		if interface == self.internal_interface:
			return {'status':False,'msg':'Interface ' + interface + " is impossible set to dhcp"}
		if otf:
			os.system('dhclient ' + interface)
		
		if interface in self.interfaces.get_list_interfaces():
			self.interfaces.change_to_dhcp(interface)
		else:
			aux_stanza_auto = lliurex.interfacesparser.StanzaAuto([interface])
			aux_stanza_dhcp = lliurex.interfacesparser.StanzaIface([interface],"inet dhcp")
			self.interfaces.insert_stanza(aux_stanza_auto)
			self.interfaces.insert_stanza(aux_stanza_dhcp)
		self.interfaces.write_file(self.path_interfaces)
		return {'status':True,'msg':'Interface ' + interface + " has been changed to dhcp"}
	
	def interface_static(self, interface, ip,netmask,otf, gateway=None,dnssearch=None):
		if otf:
			os.system('ifconfig '+ interface+' ' + ip + ' netmask ' + netmask)
			if gateway != None:
				os.system('route add default gw ' + gateway)
		if  interface in self.interfaces.get_list_interfaces():
			options = {'address':ip ,'netmask':netmask}
			if gateway != None:
				options['gateway'] = gateway
			if dnssearch != None:
				options['dns-search'] = dnssearch
			self.interfaces.change_to_static(interface,options)
		else:
			
			options = []
			if gateway != None:
				options.append("gateway " + gateway)
			if dnssearch != None:
				options.append("dns-search " + dnssearch)
			aux_stanza_auto = lliurex.interfacesparser.StanzaAuto([interface])
			aux_stanza_static = lliurex.interfacesparser.StanzaIface([interface],"inet dhcp")
			aux_stanza_static.change_to_static(ip,netmask,options)
			self.interfaces.insert_stanza(aux_stanza_auto)
			self.interfaces.insert_stanza(aux_stanza_static)
		
		self.interfaces.write_file(self.path_interfaces)
		if interface == self.internal_interface:
			objects['VariablesManager'].init_variable('INTERNAL_NETWORK',{'ip':ip,'netmask':netmask})
			objects['VariablesManager'].init_variable('INTERNAL_MASK',{'internal_mask':netmask})
			objects['VariablesManager'].init_variable('SRV_IP',{'ip':ip})
			
			# Restarting internal interface. Initialization behaves better this way
			os.system("ip addr flush dev %s"%interface)
			os.system("ifdown %s; ifup %s"%(interface,interface))
		
		
		return {'status':True,'msg':'Interface ' + interface + " has been changed to static "}
	
	
	def get_info_eth(self,eth):
		if type(eth) == type(""):
			return {'status':True,'msg':lliurex.net.get_device_info(eth)}
		else:
			return {'status':False,'msg':'eth must to be string'}
	#def get_info_eth
	
	def set_nat(self, enable=True, persistent=False , eth=None):
		if eth == None:
			if self.external_interface == None:
				return {'status':False,'msg':'External interface is not defined'}
			else:
				eth = self.external_interface
		if persistent:
			try:
				if enable:
					self.interfaces.enable_nat([eth],'/usr/share/n4d-network/list_internal_interfaces')
				else:
					self.interfaces.disable_nat([eth])
			except Exception as e:
				return {'status':False,'msg':e.message}
			self.interfaces.write_file(self.path_interfaces)
		script = ['enablenat']
		if enable:
			script.append('A')
		else:
			script.append('D')
		script.append('/usr/share/n4d-network/list_internal_interfaces')
		script.append(eth)
		p = subprocess.Popen(script,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		result = p.communicate()[0]
		return {'status':True,'msg':'nat is set'}
	#def set_nat
	
	def get_nat(self):
		if self.external_interface == None:
			return {'status':False,'msg':'External interface is not defined'}
		p = subprocess.Popen(['iptables-save','-t','nat'],stdout=subprocess.PIPE,stdin=subprocess.PIPE)
		output = p.communicate()[0].split('\n')
		needle = "-A POSTROUTING -o "+self.external_interface+" -j MASQUERADE"
		if (needle in output):
			return {'status':True,'msg':'Nat is activated'}
		else:
			return {'status':False,'msg':'Nat is not activated'}
	#def get_nat
	
	def set_routing(self, enable=True, persistent=False):
		if enable:
			self.interfaces.enable_forwarding_ipv4(persistent)
		else:
			self.interfaces.disable_forwarding_ipv4(persistent)
		return {'status':True,'msg': 'routing set'}
	#def set_routing
	
	def get_routing(self):
		ret=self.interfaces.is_enable_forwarding_ipv4()
		if ret:
			msg="Routing is enabled"
		else:
			msg="Routing is disabled"
		return {'status':ret,'msg':msg}
	#def get_routing

	def get_nat_persistence(self):
		if self.external_interface != None:
			result = self.interfaces.get_nat_persistent(self.external_interface)
			status = 'enabled' if result else 'disabled'
		else:
			result = False
			status = 'disabled'
		return {'status': result,'msg' : 'Nat persistence is ' + status }
	#def get_nat_persistent

	def get_routing_persistence(self):
		result = self.interfaces.get_routing_persistent('ipv4')
		if result :
			return {'status':result,'msg':'Routing persistent is enabled'}
		else:
			return {'status':result,'msg':'Routing persistent is disabled'}
	#def get_routing_persistent

	def disable_network_manager(self):
		return {'status':False,'msg': 'Removed dependency of upstart-manager from lliurex-disable-upstart-services, need to fix? /usr/share/n4d/python-plugins/NetworkManager.py from n4d-network'}
		script = ['/usr/sbin/upstart-manager','network-manager']
		p = subprocess.Popen(script,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		result = p.communicate()[0]
		script = ['stop','network-manager']
		p = subprocess.Popen(script,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		result = p.communicate()[0]
		return {'status':True,'msg': 'Network Manager is disabled ^_^'}
	#def disable_network_manager
	
	def restart_interfaces(self):
		result = os.system('/etc/init.d/networking restart')
		
		for interface in lliurex.net.get_devices_info():
			os.system("ip addr flush dev %s"%interface["name"])
			os.system("ifdown %s;ifup %s"%(interface["name"],interface["name"]))
			
		if (result == 0):
			return {'status':True,'msg':'network is restarted ok'}
		else:
			return {'status':False,'msg':'network has a problem. Please check file'}
	#def restart_interfaces
	
	def makedir(self,dir_path=None):
		
		if not os.path.isdir(dir_path):
			os.makedirs(dir_path)
		
		return [True]
		
	# def makedir
	
	
	def backup(self,dir_path="/backup"):
		
		
		try:
		
			self.makedir(dir_path)
			file_path=dir_path+"/"+get_backup_name("NetworkManager")
			
				
			tar=tarfile.open(file_path,"w:gz")
			
			for f in self.backup_files:
				if os.path.exists(f):
					tar.add(f)
					
			#for
			
			tar.close()
			print "Backup generated in %s" % file_path	
			return [True,file_path]
			
			
		except Exception as e:
				print "Backup failed", e
				return [False,str(e)]
		
	#def backup
	
	def restore(self,file_path=None):
		
				
		
		#Ordeno de manera alfabetica el directorio y busco el fichero que tiene mi cadena
		if file_path==None:
			dir_path="/backup"
			for f in sorted(os.listdir(dir_path),reverse=True):
				
				if "NetworkManager" in f:
					file_path=dir_path+"/"+f
					break
			
		#Descomprimo el fichero y solo las cadenas que espero encontrar son las que restauro, reiniciando el servicio
		
		print "Trabajare con este fichero", file_path
		try:
			if os.path.exists(file_path):
				tmp_dir=tempfile.mkdtemp()
				tar=tarfile.open(file_path)
				tar.extractall(tmp_dir)
				tar.close
				for f in self.backup_files:
						tmp_path=tmp_dir+f
						if os.path.exists(tmp_path):
							shutil.copy(tmp_path,f)
							
				
						
				if os.path.exists(self.rules_file):
					os.remove(self.rules_file)
					
			os.system("/etc/init.d/networking restart")
			print "File is restored in %s" % self.backup_files
			
			return [True,""]
		
		
		except Exception as e:
			
			print "Restored failed", e
			return [False,str(e)]
		
		pass
		
	#def restore
	
	
if __name__ == '__main__':
	e = NetworkManager()
	print e.get_interfaces()
