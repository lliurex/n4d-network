import dbus
from yaml import load as load_yaml
from tarfile import open as tar_open
from pathlib import Path
from tempfile import NamedTemporaryFile, mkdtemp
from netaddr import IPNetwork, IPAddress
from shutil import copy as shutil_copy
import subprocess

from n4d.server.core import Core
from n4d.utils import get_backup_name
import n4d.responses
import lliurex.net

class NetworkManager:

    # ERROR LIST
    VALUE_MUST_BE_STRING = -10
    EXTERNAL_INTERFACE_NOT_DEFINED = -20
    REPLICATION_INTERFACE_NOT_DEFINED = -21
    NOT_EXISTS_REPLICATION_CONFIG = -30
    DHCP_NOT_POSIBLE = -40
    BACKUP_FAILED = -50
    
    def __init__(self):
        self.core = Core.get_core()
        self.systembus = dbus.SystemBus()
        systemd1 = self.systembus.get_object('org.freedesktop.systemd1','/org/freedesktop/systemd1')
        self.systemdmanager = dbus.Interface(systemd1,'org.freedesktop.systemd1.Manager')
        self.network_file = Path("/etc/netplan/20-lliurex.yaml")
        self.replication_network_file = Path("/etc/netplan/30-replication-lliurex.yaml")
        self.routing_path = Path("/etc/sysctl.d/10-lliurex-forwarding.conf")
        self.resolved_path = Path("/etc/systemd/resolved.conf.d/lliurex-dnsmasq.conf")
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

    def set_replicate_interface(self, interface ):
        self.core.set_variable("INTERFACE_REPLICATION", interface)
        return n4d.responses.build_successful_call_response(True, "Interface {0} is replication interface now".format(interface) )
    #def set_replicate_interface

    def interface_dhcp(self, interface):
        if interface == self.core.get_variable("INTERNAL_INTERFACE"):
            return n4d.responses.build_failed_call_response(NetworkManager.DHCP_NOT_POSIBLE)

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
            return n4d.responses.build_failed_call_response(NetworkManager.NOT_EXISTS_REPLICATION_CONFIG)
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
            return n4d.responses.build_failed_call_response(NetworkManager.VALUE_MUST_BE_STRING)
    #def get_info_eth


    def set_nat(self, enable=True, persistent=False , eth=None):
        if not isinstance(eth,str):
            return n4d.responses.build_failed_call_response(NetworkManager.VALUE_MUST_BE_STRING)
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
            return n4d.responses.build_failed_call_response(NetworkManager.VALUE_MUST_BE_STRING)
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
        if external_interface is None:
            return n4d.responses.build_failed_call_response(NetworkManager.EXTERNAL_INTERFACE_NOT_DEFINED)
            
        p = subprocess.Popen(['iptables-save','-t','nat'],stdout=subprocess.PIPE,stdin=subprocess.PIPE)
        output = p.communicate()[0].split('\n')
        needle = "-A POSTROUTING -o " + external_interface + " -j MASQUERADE"
        if (needle in output):
            return n4d.responses.build_successful_call_response( True, "Nat is activated" )
        else:
            return n4d.responses.build_successful_call_response( False, "Nat is not activated" )
    #def get_nat

    def get_nat_replication(self):
        replication_interface = self.core.get_variable("INTERFACE_REPLICATION")
        if replication_interface is None:
            return n4d.responses.build_failed_call_response(NetworkManager.REPLICATION_INTERFACE_NOT_DEFINED)
        p = subprocess.Popen(['iptables-save','-t','nat'],stdout=subprocess.PIPE,stdin=subprocess.PIPE)
        output = p.communicate()[0].split('\n')
        needle = "-A POSTROUTING -o " + replication_interface
        if needle in output and '-j SNAT' in output:
            return n4d.responses.build_successful_call_response(True, 'Nat is activated')
        return n4d.responses.build_successful_call_response(False,'Nat is not activated')
    #def get_nat_replication    

    def set_routing(self, enable=True, persistent=False):
        value = "1" if enable else "0"
        with Path('/proc/sys/net/ipv4/ip_forward').open('w', encoding='utf-8') as fd:
            fd.write(value)
        with Path('/proc/sys/net/ipv6/conf/all/forwarding').open('w', encoding='utf-8') as fd:
            fd.write(value)

        if persistent:
            if enable:
                self.change_option_sysctl(self.routing_path,'net.ipv4.ip_forward','net.ipv4.ip_forward=1')
                self.change_option_sysctl(self.routing_path,'net.ipv6.conf.all.forwarding','net.ipv6.conf.all.forwarding=1')
            else:
                self.change_option_sysctl(self.routing_path,'net.ipv4.ip_forward','net.ipv4.ip_forward=0')
                self.change_option_sysctl(self.routing_path,'net.ipv6.conf.all.forwarding','net.ipv6.conf.all.forwarding=0')
        return n4d.responses.build_successful_call_response(True)
    #def set_routing

    def get_routing(self):
        ret = False
        try:
            with Path('/proc/sys/net/ipv4/ip_forward').open('r',encoding='utf-8') as fd:
                ret = fd.readlines()[0].strip() == "1"
        except:
            pass
        msg_value = "enabled" if ret else "disabled"
        return n4d.responses.build_successful_call_response(ret,msg='Routing is {msg_value}'.format(msg_value=msg_value) )
    #def get_routing


    def change_option_sysctl(self, file_path, needle,value):
        if file_path.exists():
            with file_path.open('r',encoding='utf-8') as fd:
                lines = fd.readlines()
        else:
                lines = []
        found = False
        with file_path.open('w',encoding='utf-8') as fd:
            for x in lines:
                if needle in x:
                    fd.write("{0}\n".format(value))
                    found = True
                    continue
                fd.write(x)
            if not found:
                fd.write("{0}\n".format(value))
    #def change_option_sysctl

    def is_static(self, interface):
        try:
            if len(self.config['network']['ethernets'][interface]['addresses']) > 0:
                return n4d.responses.build_successful_call_response(True,'Interface {interface} has static configuration'.format(interface=interface))
        except:
            pass
        return n4d.responses.build_successful_call_response(False, 'Interface {interface} has dynamic configuration'.format(interface=interface) )
    #def is_static

    def systemd_resolv_conf(self):
        conf = "[Resolve]\nDNS=127.0.0.1\nDNSStubListener=no\n"
        self.resolved_path.parent.mkdir(parents=True, exist_ok=True)
        with self.resolved_path.open('w', encoding='utf-8') as fd:
            fd.write(conf)
        self.systemdmanager.RestartUnit("systemd-resolved.service","replace")
        return n4d.responses.build_successful_call_response(True)
    #def systemd_resolv_conf

    def apply_changes(self):
        os.system('netplan apply')
        if self.resolved_path.exists(): 
            self.systemdmanager.RestartUnit("systemd-resolved.service","replace")
        return n4d.responses.build_successful_call_response(True)
    #def apply_changes

    def check_devices(self, list_devices_name, timeout=90):
        all_devices ={}
        general_network = self.systembus.get_object('org.freedesktop.network1','/org/freedesktop/network1')
        general_network_interface = dbus.Interface(general_network, 'org.freedesktop.network1.Manager')
        for x in general_network_interface.ListLinks():
            if x[1] in list_devices_name:
                all_devices[x[1]]= x[2]
        for x in  all_devices.keys():
            w = self.systembus.get_object('org.freedesktop.network1', all_devices[x])
            z = dbus.Interface(w, 'org.freedesktop.DBus.Properties')
            if z.Get('org.freedesktop.network1.Link','OperationalState') != 'routable':
                return n4d.responses.build_successful_call_response(False)
        return n4d.responses.build_successful_call_response(True)


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

    def get_routing_persistence(self):
        with self.routing_path.open('r',encoding='utf-8') as fd:
            s = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)
            if s.find(b'net.ipv4.ip_forward=') == -1:
                return n4d.responses.build_successful_call_response( False, 'Routing persistent is disabled' )
        return n4d.responses.build_successful_call_response( True, 'Routing persistent is enabled' )
    #def get_routing_persistent

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
            return n4d.responses.build_failed_call_response(NetworkManager.BACKUP_FAILED, "[NetworkManager] backup failed {0}".format(str(e)))
    #def backup

    def restore(self, backupfile=None):
        if backupfile is None:
            dir_path = Path('/backup')
            for f in dir_path.iterdir():
                if f.name == 'NetworkManager':
                    file_path = f
                    break
        else:
            file_path = Path(backupfile)

        if file_path.exists():
            tmp_dir = Path(mkdtemp())
            tar = tar_open(file_path)
            tar.extractall(tmp_dir)
            tar.close()
            
            if tmp_dir.joinpath('nat').exists():
                external_interface = 'eth1'
                with tmp_dir.joinpath('nat').open('r',encoding='utf-8') as fd:
                    external_interface = fd.readline().strip()
                self.set_nat( True, True, external_interface )

            for f in self.backup_files:
                print("Restoring {0}".format(f))
                tmp_path = tmp_dir.joinpath(f.relative_to('/'))
                if tmp_path.exists():
                    shutil_copy(tmp_path, f)
        self.apply_changes()
        return n4d.responses.build_successful_call_response("True")
    #def restore






