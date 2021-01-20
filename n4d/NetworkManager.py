import dbus
from yaml import load_yaml
from tar import open as tar_open
from pathlib import Path
from tempfile import NamedTemporaryFile
from netaddr import IPNetwork, IPAddress
import subprocess

from n4d.server.core import Core
from n4d.utils import get_backup_name
import n4d.responses
import lliurex.net



class NetworkManager:
    def __init__(self):
        self.core = Core.get_core()
        self.systembus = dbus.SystemBus()
        systemd1 = self.systembus.get_object('org.freedesktop.systemd1','/org/freedesktop/systemd1')
        self.systemdmanager = dbus.Interface(systemd1,'org.freedesktop.systemd1.Manager')
        self.network_file = Path("/etc/netplan/20-lliurex.yaml")
        self.replication_network_file = Path("/etc/netplan/30-replication-lliurex.yaml")
        self.routing_path = "/etc/sysctl.d/10-lliurex-forwarding.conf"
        self.interfaces="/etc/network/interfaces"
        self.backup_files=[ self.network_file, self.replication_network_file, self.routing_path, self.interfaces ]

        self.network_file.touch()
        self.replication_network_file.touch()
        self.load_network_file()
    #def __init__

    def dprint(self, data):
        if self.core.DEBUG:
            print("[NetworkManager] {0}".format(data))
    #def dprint

    def load_network_file(self):
        self.config = self.load_network_config(self.network_file)
        self.replication_config = self.load_network_config(self.replication_network_file)
        return n4d.responses.build_successful_call_response(True,"Network configuration and replication files has been read")
    #def load_network_file

    def load_network_config( self, path_file ):
        with path_file.open( 'r', encoding='utf-8' ) as fd:
            config = load_yaml( fd )
        
        if config is None:
            config = {}
        if not "network" in config:
            config["network"] = {}
        if not "version" in config["network"]:
            config["network"]["version"] = 2

        return config
    #def load_network_config

    def set_internal_interface(self, interface):
        self.core.set_variable("INTERNAL_INTERFACE", interface)
        ip = None
        try:
            ip = IPNetwork(self.config["network"]["ethernets"][interface]["addresses"][0])
        except:
            ip = lliurex.net.get_IPNewtork_object(interface)
        if ip is not None:
            self.set_n4d_network_vars(ip)
        return n4d.responses.build_successful_call_response(True, "Set internal interface")
    #def set_internal_interface

    def set_n4d_network_vars( self, ip ):
        self.core.set_variable("SRV_IP", str(ip.ip))
        self.core.set_variable("INTERNAL_NETWORK",str(ip.network))
        self.core.set_variable("INTERNAL_MASK",ip.prefixlen)
    #def set_n4d_network_vars

    def set_external_interface( self, interface ):
        self.core.set_variable( "EXTERNAL_INTERFACE", interface )
        return n4d.responses.build_successful_call_response( True, "Set {0} as external interface".format( interface ) )
    #def set_external_interface

    def interface_dhcp(self, interface):
        if interface == self.core.get_variable("INTERNAL_INTERFACE"):
            return n4d.responses.build_failed_call_response(False, "Interface {interface} is impossible set to dhcp".format(interface=interface))
        
        self.secure_delete_key_dictionary(self.config,['network','ethernets',interface])
        self.secure_insert_dictionary(self.config,['network','ethernets',interface,'dhcp4'],True)
        self.secure_insert_dictionary(self.config,['network','ethernets',interface,'dhcp4-overrides','use-dns'],False)
        self.secure_insert_dictionary(self.config,['network','ethernets',interface,'dhcp4-overrides','use-domains'],False)
        self.secure_insert_dictionary(self.config,['network','ethernets',interface,'dhcp6'],True)
        self.secure_insert_dictionary(self.config,['network','ethernets',interface,'dhcp6-overrides','use-dns'],False)
        self.secure_insert_dictionary(self.config,['network','ethernets',interface,'dhcp6-overrides','use-domains'],False)
        self.secure_insert_dictionary(self.config,['network','ethernets',interface,'dhcp-identifier'],"mac")
        self.secure_insert_dictionary(self.config,['network','ethernets',interface,'renderer'],'networkd')

        # Falta que se escriba el fichero
        self.safe_config('network')
        return n4d.responses.build_successful_call_response(True,"Interface {interface} has been changed to dhcp".format(interface=interface) )
    
    #def interface_dhcp    

    def interface_static(self, interface, ip, netmask, gateway=None, dnssearch=None):

        ip_object = IPNetwork('{ip}/{mask}'.format(ip=ip, mask= netmask))
        self.secure_delete_key_dictionary(self.config,['network','ethernets',interface])
        self.secure_insert_dictionary(self.config,['network','ethernets',interface,'addresses',0], str(ip_object))
        self.secure_insert_dictionary(self.config,['network','ethernets',interface,'renderer'], 'networkd')
        if gateway is not None:
            self.secure_insert_dictionary(self.config,['network','ethernets',interface,'gateway4'], gateway )
        if dnssearch is not None:
            self.secure_insert_dictionary(self.config,['network','ethernets',interface,'nameservers','search',0], dnssearch)
        if self.core.get_variable("INTERNAL_INTERFACE") == interface:
            self.set_n4d_network_vars(ip_object)
        self.safe_config('network')
        return n4d.responses.build_successful_call_response(True, "Interface {interface} has been changed to static".format(interface=interface))
    #def interface_static

    def set_replication_interface(self, interface, ip=None, netmask=None, enabled=True):
        msg = ''
        if not enabled:
            self.secure_delete_key_dictionary(self.replication_config,['network','ethernets'])
            msg = 'Replication interfaces has been disabled'
        elif ip is not None and netmask is not None:
            ip_object = IPNetwork('{ip}/{mask}'.format(ip=ip, mask= netmask))
            self.secure_insert_dictionary(self.replication_config,['network','ethernets',interface,'addresses',0],str(ip_object))
            msg = 'Replication interface now is {interface}'.format(interface=interface)
        self.safe_config('replication')
        return n4d.responses.build_successful_call_response(True, msg)
    #def set_replication_interface

    def safe_config(self, config_to_save):
        if config_to_save == 'network':
            config = self.config
            file_config = self.network_file
        elif config_to_save == 'replication':
            config = self.replication_config
            file_config = self.replication_network_file
        else:
            return False
        with file_config.open('w',encoding='utf-8') as stream:
            yaml.dump(config, stream)
    #def safe_config

    def get_replication_network(self):
        try:
            return n4d.responses.build_successful_call_response(self.replication_config['network']['ethernets'][self.core.get_variable("INTERFACE_REPLICATION")]['addresses'][0])
        except:
            return n4d.responses.build_failed_call_response(False, "There isn't replication config")
    #def get_replication_network

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
        if isinstance(eth, str):
            return n4d.responses.build_successful_call_response(lliurex.net.get_device_info(eth))
        else:
            return n4d.responses.build_failed_call_response(False, 'eth must to be string')
    #def get_info_eth


    def set_nat(self, enable=True, persistent=False , eth=None):
        if not isinstance(eth,str):
            return n4d.responses.build_failed_call_response(False, "eth must be string")
        msg = ''
        if enable:
            self.systemdmanager.EnableUnitFiles(['enablenat@{iface}.service'.format(iface=eth)],not persistent, True)
            self.systemdmanager.StartUnit('enablenat@{iface}.service'.format(iface=eth),'replace')
            msg = 'Nat is enabled on {eth}'.format(eth=eth)
        else:
            self.systemdmanager.DisableUnitFiles(['enablenat@{iface}.service'.format(iface=eth)],not persistent)
            self.systemdmanager.StopUnit('enablenat@{iface}.service'.format(iface=eth),'replace')
            msg = 'Nat is disabled on {eth}'.format(eth=eth)
        return n4d.responses.build_successful_call_response(True, msg)
    #def set_nat

    def set_nat_replication(self, enable=True, persistent=False, eth=None):
        if not isinstance(eth,str):
            return n4d.responses.build_failed_call_response(False, "eth must be string")
        msg = ''
        if enable:
            self.systemdmanager.EnableUnitFiles(['enablenatreplication@{iface}.service'.format(iface=eth)],not persistent, True)
            self.systemdmanager.StartUnit('enablenatreplication@{iface}.service'.format(iface=eth),'replace')
            msg = 'Nat replication is enabled on {eth}'.format(eth=eth)
        else:
            self.systemdmanager.DisableUnitFiles(['enablenatreplication@{iface}.service'.format(iface=eth)],not persistent)
            self.systemdmanager.StopUnit('enablenatreplication@{iface}.service'.format(iface=eth),'replace')
            msg = 'Nat replication is disabled on {eth}'.format(eth=eth)
        return n4d.responses.build_successful_call_response(True, msg)
    #def set_nat_replication

    def clean_nat_services(self):
        listservices = self.systemdmanager.ListUnitsByPatterns([],['enablenat*'])
        for service in listservices:
            self.systemdmanager.DisableUnitFiles([service[0].lower()],False)
            self.systemdmanager.StopUnit(service[0].lower(),'replace')
        return n4d.responses.build_successful_call_response(True,'All nat services has been disabled')
    #def clean_nat_services

    def get_nat(self):
        external_interface = self.core.get_variable("EXTERNAL_INTERFACE")
        if external_interface is None
            return n4d.responses.build_failed_call_response(False, "External interface is not defined")
        p = subprocess.Popen(['iptables-save','-t','nat'],stdout=subprocess.PIPE,stdin=subprocess.PIPE)
        output = p.communicate()[0].split('\n')
        needle = "-A POSTROUTING -o " + external_interface + " -j MASQUERADE"
        if (needle in output):
            return n4d.responses.build_successful_call_response( True, "Nat is activated" )
        else:
            return n4d.responses.build_successful_call_response( False, "Nat is not activated" )
    #def get_nat

################### VOY POR AQUI, REVISAR QUIEN PONE LA VARIABLE INTERFACE_REPLICATION


    def get_nat_persistence(self):
        result = False
        status = "disabled"
        if self.core.get_variable("EXTERNAL_INTERFACE") is not None:
            try:
                status = str(self.systemdmanager.GetUnitFileState('enablenat.service'))
                result = status == 'enabled'
            except:
                result = False
                status = "disabled"
        return n4d.responses.build_successful_call_response(result, "Nat persistence is {0}".format(status))
    #def get_nat_persistence

    def backup(self,dir_path="/backup"):
        try:
            backup_dir = Path(dir_path)
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            file_path = backup_dir.joinpath( get_backup_name( "NetworkManager" ) )
            
            tar = tar_open( file_path, "w:gz" )
            
            for f in self.backup_files:
                if Path(f).exists():
                    tar.add(f)
            if self.get_nat_persistence()['return']:
                aux_file = NamedTemporaryFile('w', delete=False, encoding='utf-8')
                aux_file_path = Path(aux_file.name)
                aux_file.file.write( self.external_interface )
                tar.add( aux_file.name, arcname='nat' )

            tar.close()
            if "aux_file_path" in locals and aux_file_path.exists():
                aux_file_path.unlink()

            self.dprint("Backup generated in {}".format(file_path))
            return n4d.responses.build_successful_call_response( str( file_path ) )
            
        except Exception as e:
            self.dprint("Backup failed: {0}".format(str(e)))
            return n4d.responses.build_failed_call_response(False, "[NetworkManager] backup failed {0}".format(str(e)))
    #def backup
    