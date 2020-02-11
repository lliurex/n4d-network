import lliurex.net
import dbus
import yaml
from netaddr import IPNetwork, IPAddress
import os
import subprocess
import mmap
import tarfile
import tempfile
import NetworkManager as nm
import time

class NetworkManager:
	def __init__(self):
		with open('/etc/nat_enabler.conf','w') as fd:
			fd.write('PATH_INTERNAL_INTERFACES=/usr/share/n4d-network/list_internal_interfaces')
		self.systembus = dbus.SystemBus()
		systemd1 = self.systembus.get_object('org.freedesktop.systemd1','/org/freedesktop/systemd1')
		self.systemdmanager = dbus.Interface(systemd1,'org.freedesktop.systemd1.Manager')
		self.rules_file="/etc/udev/rules.d/70-persistent-net.rules"
		self.network_file = "/etc/netplan/20-lliurex.yaml"
		self.replication_network_file = "/etc/netplan/30-replication-lliurex.yaml"
		self.routing_path = "/etc/sysctl.d/10-lliurex-forwarding.conf"
		self.interfaces="/etc/network/interfaces"
		self.backup_files=[ self.network_file, self.replication_network_file, self.routing_path, self.interfaces ]
		
		self.exists_or_create(self.network_file)
		self.exists_or_create(self.replication_network_file)
		self.load_network_file()
		
	#def __init__
		
	def exists_or_create(self, file_path):
		if not os.path.exists(file_path):
			with open(file_path,'w') as fd:
				pass
	#def exists_or_create
	
	def startup(self,options):
		self.internal_interface = objects['VariablesManager'].get_variable('INTERNAL_INTERFACE')
		self.external_interface = objects['VariablesManager'].get_variable('EXTERNAL_INTERFACE')
		self.replication_interface = objects['VariablesManager'].get_variable('INTERFACE_REPLICATION')
	#def startup
	
	def get_interfaces(self):
		return {'status':True,'msg':[x['name'] for x in lliurex.net.get_devices_info()]}
	#def get_interfaces

	def load_network_file(self):
		self.config = self.load_network_config(self.network_file)
		self.replication_config = self.load_network_config(self.replication_network_file)
		return {'status': True, 'msg':'Network configuration and replication configuration files has been read'}
	#def load_network_file

	def load_network_config(self, path_file):
		
		with open(path_file) as fd:
			config = yaml.load(fd)
		
		if config is None:
			config = {}

		if not 'network' in config:
			config['network'] = {}
		
		if not 'version' in config['network']:
			config['network']['version'] = 2
#		if not 'renderer' in config['network']:
#			config['network']['renderer'] = 'NetworkManager'
		return config
	
	def set_internal_interface(self, interface):

		ip, netmask = None, None

		objects['VariablesManager'].init_variable('INTERNAL_INTERFACE',{'internal_interface':interface})
		self.internal_interface = interface
		try:
			ip = self.config['network']['ethernets'][interface]['addresses'][0]
			netmask = str(IPNetwork(ip).netmask)
		except:
			pass
			ip = lliurex.net.get_ip(interface)
		if(netmask == None):
			netmask = lliurex.net.get_netmask(interface)
			
		if (ip != None and netmask != None):
			self.set_n4d_network_vars(ip, netmask)
		return {'status':True,'msg':'internal interface'}
		
	#def set_internal_interfaces

	def set_n4d_network_vars(self, ip, netmask):
		objects['VariablesManager'].init_variable('INTERNAL_NETWORK',{'ip':ip,'netmask':netmask})
		objects['VariablesManager'].init_variable('INTERNAL_MASK',{'internal_mask':netmask})
		objects['VariablesManager'].init_variable('SRV_IP',{'ip':ip})
	#def set_n4d_network_vars

	def set_external_interface(self, interface):
		objects['VariablesManager'].init_variable('EXTERNAL_INTERFACE',{'external_interface':interface})
		self.external_interface = interface
		return {'status':True,'msg':'external interface'}
	#def set_external_interface

	def interface_dhcp(self, interface):
		if interface == self.internal_interface:
			return {'status':False,'msg':'Interface ' + interface + " is impossible set to dhcp"}
		
		self.secure_delete_key_dictionary(self.config,['network','ethernets',interface])
		self.secure_insert_dictionary(self.config,['network','ethernets',interface,'dhcp4'],True)
		self.secure_insert_dictionary(self.config,['network','ethernets',interface,'dhcp4-overrides','use-dns'],False)
		self.secure_insert_dictionary(self.config,['network','ethernets',interface,'dhcp4-overrides','use-domains'],False)
		self.secure_insert_dictionary(self.config,['network','ethernets',interface,'dhcp6'],True)
		self.secure_insert_dictionary(self.config,['network','ethernets',interface,'dhcp6-overrides','use-dns'],False)
		self.secure_insert_dictionary(self.config,['network','ethernets',interface,'dhcp6-overrides','use-domains'],False)
		self.secure_insert_dictionary(self.config,['network','ethernets',interface,'renderer'],'networkd')

		# Falta que se escriba el fichero
		self.safe_config('network')
		return {'status':True,'msg':'Interface ' + interface + " has been changed to dhcp"}
	
	#def interface_dhcp

	def interface_static(self, interface, ip, netmask, gateway=None, dnssearch=None):

		bits_netmask = IPAddress(netmask).netmask_bits()
		self.secure_delete_key_dictionary(self.config,['network','ethernets',interface])
		self.secure_insert_dictionary(self.config,['network','ethernets',interface,'addresses',0], '{ip}/{mask}'.format(ip=ip,mask=bits_netmask))
		self.secure_insert_dictionary(self.config,['network','ethernets',interface,'renderer'], 'networkd')
		if gateway is not None:
			self.secure_insert_dictionary(self.config,['network','ethernets',interface,'gateway4'], gateway )
		if dnssearch is not None:
			self.secure_insert_dictionary(self.config,['network','ethernets',interface,'nameservers','search',0], dnssearch)
		if self.internal_interface == interface:
			self.set_n4d_network_vars(ip, netmask)
		self.safe_config('network')
		return {'status':True,'msg':'Interface ' + interface + " has been changed to static "}
	#def interface_static

	def set_replication_interface(self, interface, ip=None, netmask=None, enabled=True):
		msg = ''
		if not enabled:
			self.secure_delete_key_dictionary(self.replication_config,['network','ethernets'])
			msg = 'Replication interfaces has been disabled'
		elif ip is not None and netmask is not None:
			bits_netmask = IPAddress(netmask).netmask_bits()
			self.secure_insert_dictionary(self.replication_config,['network','ethernets',interface,'addresses',0],'{ip}/{mask}'.format(ip=ip, mask=bits_netmask))
			msg = 'Replication interface now is {interface}'.format(interface=interface)
		self.safe_config('replication')
		return {'status':True,'msg':msg}
	#def set_replication_interface

	def safe_config(self, config_to_save):
		if config_to_save == 'network':
			config = self.config
			file_config = self.network_file
		elif config_to_save == 'replication':
			config = self.replication_config
			file_config = self.replication_network_file

		with open(file_config,'w') as stream:
			yaml.dump(config, stream)
	#def safe_config


	def secure_insert_dictionary(self, target, key_path, value):
		temp_target = target
		for index in range(0, len(key_path) - 1): 
			key_path_key = key_path[index]
			type_value = type(key_path_key)
			found = False
			if type_value == int:
				try:
					variable_useless = temp_target[key_path_key]
					found = True if not variable_useless is None else False
				except:
					pass
			elif type_value == str:
				if key_path_key in temp_target:
					found = True
			if not found:
				if isinstance(temp_target, list) and isinstance(key_path_key, int)\
									  and (len(temp_target) - 1) < key_path_key:
					while (len(temp_target)-1) < key_path_key:
						temp_target.append(None)
				if isinstance(key_path[index+1], int):
					temp_target[key_path_key] = []
				else:
					temp_target[key_path_key] = {}
			temp_target = temp_target[key_path_key]

		if isinstance(temp_target, list) and isinstance(key_path[-1], int) and \
										(len(temp_target) - 1) < key_path[-1]:
			while (len(temp_target)-1) < key_path[-1]:
				temp_target.append(None)
		temp_target[key_path[-1]] = value
		return target
	#def secure_insert_dictionary

	def secure_delete_key_dictionary(self, target, key_path):
		temp_target = target
		for key in key_path[:-1]:
			if isinstance(key, str) and (key not in temp_target):
				return True
			if isinstance(key, int) and key >= len(temp_target):
				return True
			temp_target = temp_target[key]
		try:
			del temp_target[key_path[-1]]
		except (IndexError, KeyError):
			pass
	#def secure_delete_key_dictionary

	def get_info_eth(self,eth):
		if type(eth) == type(""):
			return {'status':True,'msg':lliurex.net.get_device_info(eth)}
		else:
			return {'status':False,'msg':'eth must to be string'}
	#def get_info_eth
	
	def set_nat(self, enable=True, persistent=False , eth=None):
		msg = ''
		if enable:
			self.systemdmanager.EnableUnitFiles(['enablenat@{iface}.service'.format(iface=eth)],not persistent, True)
			self.systemdmanager.StartUnit('enablenat@{iface}.service'.format(iface=eth),'replace')
			msg = 'Nat is enabled on {eth}'.format(eth=eth)
		else:
			self.systemdmanager.DisableUnitFiles(['enablenat@{iface}.service'.format(iface=eth)],not persistent)
			self.systemdmanager.StopUnit('enablenat@{iface}.service'.format(iface=eth),'replace')
			msg = 'Nat is disabled on {eth}'.format(eth=eth)
		return {'status': True, 'msg':msg}
	#def set_nat

	def set_nat_replication(self, enable=True, persistent=False, eth=None):
		msg = ''
		if enable:
			self.systemdmanager.EnableUnitFiles(['enablenatreplication@{iface}.service'.format(iface=eth)],not persistent, True)
			self.systemdmanager.StartUnit('enablenatreplication@{iface}.service'.format(iface=eth),'replace')
			msg = 'Nat replication is enabled on {eth}'.format(eth=eth)
		else:
			self.systemdmanager.DisableUnitFiles(['enablenatreplication@{iface}.service'.format(iface=eth)],not persistent)
			self.systemdmanager.StopUnit('enablenatreplication@{iface}.service'.format(iface=eth),'replace')
			msg = 'Nat replication is disabled on {eth}'.format(eth=eth)
		return {'status': True, 'msg':msg}


	def clean_nat_services(self):
		listservices = self.systemdmanager.ListUnitsByPatterns([],['enablenat*'])
		for service in listservices:
			self.systemdmanager.DisableUnitFiles([service[0].lower()],not persistent)
			self.systemdmanager.StopUnit(service[0].lower(),'replace')
		return {'status': True, 'msg':'All nat services has been disabled'}
	#def clean_nat_services

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

	def get_nat_replication(self):
		if self.replication_interface == None:
		    return {'status':False,'msg':'External interface is not defined'}
		p = subprocess.Popen(['iptables-save','-t','nat'],stdout=subprocess.PIPE,stdin=subprocess.PIPE)
		output = p.communicate()[0].split('\n')
		needle = "-A POSTROUTING -o "+self.replication_interface
		if (needle in output):
			if ( '-j SNAT' in output):
			return {'status':True,'msg':'Nat is activated'}
		return {'status':False,'msg':'Nat is not activated'}
	#def get_nat_replication

	def set_routing(self, enable=True, persistent=False):
		value = "1" if enable else "0"
		with open('/proc/sys/net/ipv4/ip_forward','w') as fd:
			fd.write(value)
		with open('/proc/sys/net/ipv6/conf/all/forwarding','w') as fd:
			fd.write(value)
		if persistent:
			if enable:
				self.change_option_sysctl(self.routing_path,'net.ipv4.ip_forward','net.ipv4.ip_forward=1')
				self.change_option_sysctl(self.routing_path,'net.ipv6.conf.all.forwarding','net.ipv6.conf.all.forwarding=1')
			else:
				self.change_option_sysctl(self.routing_path,'net.ipv4.ip_forward','net.ipv4.ip_forward=0')
				self.change_option_sysctl(self.routing_path,'net.ipv6.conf.all.forwarding','net.ipv6.conf.all.forwarding=0')
		return {'status': True, 'msg':''}
	#def set_routing
	
	def get_routing(self):
		ret = False
		try:
			with open('/proc/sys/net/ipv4/ip_forward','r') as fd:
				ret = fd.readlines()[0].strip() == "1"
		except:
			pass
		msg_value = "enabled" if ret else "disabled"
		return {'status':ret,'msg':'Routing is {msg_value}'.format(msg_value=msg_value)}
	#def get_routing

	def get_nat_persistence(self):
		if self.external_interface != None:
			try:
				status = str(self.systemdmanager.GetUnitFileState('enablenat.service'))
				result = status == 'enabled'
			except:
				result=False
				status='disabled'	
		else:
			result = False
			status = 'disabled'
		return {'status': result,'msg' : 'Nat persistence is ' + status }
	#def get_nat_persistent

	def get_routing_persistence(self):
		with open(self.routing_path,'r') as fd:
			s = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)
			if s.find('net.ipv4.ip_forward=') == -1:
				return {'status':False, 'msg':'Routing persistent is disabled'}

		return {'status':True,'msg':'Routing persistent is enabled'}
	#def get_routing_persistent

	def change_option_sysctl(self, file_path, needle,value):
		if (os.path.exists(file_path)):
				f = open(file_path,'r')
				lines = f.readlines()
				f.close()
		else:
				lines = []
		found = False
		f = open(file_path,'w')
		for x in lines:
				if(needle in x): 
						f.write(value+"\n")
						found = True
						continue
				f.write(x)
		if (not found):
				f.write(value+"\n")
		f.close()

	def is_static(self, interface):
		try:
			if len(self.config['network']['ethernets'][interface]['addresses']) > 0:
				return {'result': True, 'msg': 'Interface {interface} has static configuration'.format(interface=interface)}
		except:
			pass
		return {'result': False, 'msg': 'Interface {interface} has dynamic configuration'.format(interface=interface)}

	def systemd_resolved_conf(self):

		path = "/etc/systemd/resolved.conf.d/"
		file_path = "lliurex-dnsmasq.conf"
		conf="[Resolve]\nDNS=127.0.0.1\nDNSStubListener=no\n"
		if not os.path.exists(path):
			os.makedirs(path)

		with open(path + file_path, "w") as fd:
			fd.write(conf)
		os.system('systemctl restart systemd-resolved')
		return {"status":True,"msg":""}

	#def systemd_resolved_conf

	
	def apply_changes(self):
		os.system('netplan apply')
		if os.path.exists("/etc/systemd/resolved.conf.d/lliurex-dnsmasq.conf"):
			os.system('systemctl restart systemd-resolved')
		return {"status": True, "msg":""}
	#def restart_interfaces
	
	def check_devices(self, list_devices_name, timeout = 90):
		class device():
			State=0
			Interface=''

		orig_time = time.time()
		all_ok = True
		list_devices=[]
		try:
			devices_str=subprocess.check_output("networkctl")
			devices_arr=devices_str.split('\n')
			for devices_line in devices_arr:
				list_devices_arr=devices_line.split()
				netdevice=device()
				if list_devices_arr:
					netdevice.Interface=list_devices_arr[1]
					if netdevice.Interface in list_devices_name:
						list_devices.append(netdevice)
		except Exception as e:
			all_ok=False
		#Device list is loaded, proceed with checks

		if all_ok:
			try:
				while True:
					devices_str=subprocess.check_output("networkctl")
					devices_arr=devices_str.split('\n')
					all_ok=True
					for netdevice in list_devices:
						for devices_line in devices_arr:
							if netdevice.Interface in devices_line:
								if 'routable' in devices_line:
									netdevice.State=100
								else:
									all_ok=False
									break
						time.sleep(0.1)

					if all_ok:
						break
					new_time = time.time()
					diff = new_time - orig_time
					if diff > timeout:
						all_ok= False
						break
					time.sleep(1)
			except Exception as e:
				all_ok= False
		if all_ok:
			for x in list_devices:
				found = True
				while True:
					if x.State == 100:
						break
					new_time = time.time()
					diff = new_time - orig_time
					if diff > timeout:
						found = False
						break
					time.sleep(1)
				if not found :
					all_ok = False
		return {"status": all_ok, "msg":""}

	def makedir(self,dir_path=None):
		
		if not os.path.isdir(dir_path):
			os.makedirs(dir_path)
		
		return [True]
		
	# def makedir

	def backup(self,dir_path="/backup"):
		try:
		
			self.makedir(dir_path)
			file_path=dir_path+"/"+get_backup_name("NetworkManager")
			aux_file_path = ''
			
			tar=tarfile.open(file_path,"w:gz")
			
			for f in self.backup_files:
				if os.path.exists(f):
					tar.add(f)
			if self.get_nat_persistence()['status']:
				aux_file_path = tempfile.mktemp()
				with open(aux_file_path,'w') as fd:
					fd.write(self.external_interface)
				tar.add(aux_file_path,arcname='nat')

			tar.close()
			if os.path.exists(aux_file_path):
				os.remove(aux_file_path)
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
				sw_migrate=False
				tmp_dir=tempfile.mkdtemp()
				tar=tarfile.open(file_path)
				tar.extractall(tmp_dir)
				tar.close
				if os.path.exists(tmp_dir + '/nat'):
					external_interface = 'eth1'
					with open(tmp_dir + '/nat') as fd:
						external_interface = fd.readline().strip()
					self.set_nat(True,True,external_interface)
				for f in self.backup_files:
					print("Restoring %s"%f)
					tmp_path=tmp_dir+f
					if os.path.exists(tmp_path):
						shutil.copy(tmp_path,f)
					if f.endswith("interfaces"):
						sw_migrate=True
				if os.path.exists(self.rules_file):
					os.remove(self.rules_file)
				if sw_migrate:
					self.migrate_to_netplan()
				
			self.apply_changes()
			print "File is restored in %s" % self.backup_files
			
			return [True,""]
		
		
		except Exception as e:
			
			print "Restored failed", e
			return [False,str(e)]
		
	#def restore

	def migrate_to_netplan(self):
		#migrate from nm to np
		print("Migrate to netplan")
		nm_file="/etc/network/interfaces"
		np_tmpfile="/etc/netplan/10-ifupdown.yaml"
		replication={}
		if os.path.exists(nm_file):
			print("Calling netplan migrate")
			subprocess.call("ENABLE_TEST_COMMANDS=1 netplan migrate",shell=True)
			if os.path.exists(np_tmpfile):
				for f in [np_tmpfile,self.network_file,self.replication_network_file]:
					if os.path.exists(f):
						print("Removing %s"%f)
						os.remove(f)
				with open(np_tmpfile,'r') as f:
					try:
						f_contents=yaml.safe_load(f)
					except Exception as e:
						print("%s"%e)
				interfaces=f_contents.copy()
				print("C: %s"%interfaces)
				for interface in f_contents['network']['ethernets'].keys():
					interfaces['network']['ethernets'][interface].update({'renderer':'networkd'})
					if ':' in interface:
						#replication interface
						if not 'network' in replication.keys():
							replication['network']={}
						repiface=interface.split(":")[0]
						replication['network']['ethernets'].update({repiface:interfaces['network']['ethernets'][interface].copy()})
						interfaces['network']['ethernets'].delete(interface)
				if 'network' in interfaces.keys():
					with open(self.network_file,'w') as f:
						yaml.dump(interfaces,f,default_flow_style=False)
				if not 'network' in replication.keys():
					replication.update({'network':{'renderer':'NetworkManager','version':2}})
				with open(self.replication_network_file,'w') as f:
					yaml.dump(replication,f,default_flow_style=False)
		if os.path.exists(np_tmpfile):
			os.remove(np_tmpfile)
		print("Migrated")
	
if __name__ == '__main__':
	e = NetworkManager()
	
