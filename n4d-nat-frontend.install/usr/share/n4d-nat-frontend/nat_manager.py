import gi
gi.require_version('Gtk','3.0')

from gi.repository import Gtk
import xmlrpclib
import sys
import os
import os.path

import signal

signal.signal(signal.SIGINT, signal.SIG_DFL)

import gettext
gettext.textdomain('n4d-nat-frontend')
_ = gettext.gettext

class NatManager:
	
	def __init__(self,ip="localhost"):
		
		status=self.read_key()
		self.client=xmlrpclib.ServerProxy("https://"+ip+":9779")
		
		if not status:
			print("[!] You need root privileges to run this program [!]")
			label = Gtk.Label(_("You need root privileges to run nat-manager"))
			dialog = Gtk.Dialog("Warning", None, Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT, (Gtk.STOCK_OK, Gtk.ResponseType.ACCEPT))
			dialog.vbox.pack_start(label,True,True,10)
			label.show()
			dialog.set_border_width(6)
			response = dialog.run()
			dialog.destroy()
			sys.exit(0)
		self.status={}
		self.get_status_list()
		self.build_gui()
	
	def read_key(self):
		
		try:
			f=open("/etc/n4d/key")
			self.key=f.readline().strip("\n")
			f.close()
			return True
		except:
			return False

	#def check_perms
	
	def get_status_list(self):
		
		try:
			
			ret=self.client.get_nat("","NetworkManager")
			
			self.status["nat"]=ret["status"]
			ret=self.client.get_routing("","NetworkManager")
			self.status["routing"]=ret["status"]
			self.status["nat_persistence"]=True
			self.status["routing_persistence"]=True
			proxy_status=self.client.get_variable("","VariablesManager","CLIENT_PROXY_ENABLED")
			if proxy_status==None:
				self.proxy_var_initialized=False
				proxy_status=True
			else:
				self.proxy_var_initialized=True
			self.status["proxy"]=proxy_status
			
		except Exception as e:
			self.msg_label.set_text(_("N4D error: ") + str(e))
			#set msg error
		
	#def get_status_list

	
	def build_gui(self):
		
		builder=Gtk.Builder()
		builder.set_translation_domain('n4d-nat-frontend')
		if os.path.exists("/srv/svn/pandora/n4d-network/trunk/n4d-nat-frontend.install/usr/share/n4d-nat-frontend/rsrc/nat-manager.glade"):
			builder.add_from_file("/srv/svn/pandora/n4d-network/trunk/n4d-nat-frontend.install/usr/share/n4d-nat-frontend/rsrc/nat-manager.glade")
		else:
			builder.add_from_file("/usr/share/n4d-nat-frontend/rsrc/nat-manager.ui")
			
		self.window=builder.get_object("window")
		
		self.routing_enabled_rbutton=builder.get_object("routing_enabled_radiobutton")
		self.routing_disabled_rbutton=builder.get_object("routing_disabled_radiobutton")
		
		self.routing_enabled_rbutton.set_active(self.status["routing"])
		self.routing_disabled_rbutton.set_active(not self.status["routing"])
		
		self.nat_enabled_rbutton=builder.get_object("nat_enabled_radiobutton")
		self.nat_disabled_rbutton=builder.get_object("nat_disabled_radiobutton")
		
		self.nat_enabled_rbutton.set_active(self.status["nat"])
		self.nat_disabled_rbutton.set_active(not self.status["nat"])

		self.msg_label=builder.get_object("msg_label")
		
		self.apply_button=builder.get_object("apply_button")
		self.close_button=builder.get_object("close_button")
		
		self.apply_button.connect("clicked",self.apply_changes)
		self.close_button.connect("clicked",self.close_window)
		self.window.connect("destroy",self.close_window)
		
		self.proxy_frame=builder.get_object("proxy_frame")
		self.proxy_enabled_rb=builder.get_object("proxy_enabled_radiobutton")
		self.proxy_disabled_rb=builder.get_object("proxy_disabled_radiobutton")
		self.proxy_enabled_rb.set_active(self.status["proxy"])
		self.proxy_disabled_rb.set_active(not self.status["proxy"])
		
		self.nat_enabled_rbutton.connect("toggled",self.routing_changed)
		self.routing_enabled_rbutton.connect("toggled",self.routing_changed)
		
		if not self.status["nat"] or not self.status["routing"]:
			self.proxy_frame.set_sensitive(False)
		
		
		self.window.show_all()
		Gtk.main()
		
	#def build_gui
	
	
	def apply_changes(self,widget):
		
		self.status["routing"]=self.routing_enabled_rbutton.get_active()
		self.status["nat"]=self.nat_enabled_rbutton.get_active()
		self.status["proxy"]=self.proxy_enabled_rb.get_active()
		
		try:
			self.client.set_nat(self.key,"NetworkManager",self.status["nat"],self.status["nat_persistence"])
			self.client.set_routing(self.key,"NetworkManager",self.status["routing"],self.status["routing_persistence"])
			
			if self.status["routing"] and self.status["nat"]:
				self.set_client_proxy(self.status["proxy"])
			else:
				self.set_client_proxy(True)
				
			self.msg_label.set_text(_("Changes saved successfuly"))
		except Exception as e:
			self.msg_label.set_text(_("Operation failed because: ") + str(e))
		
		
	#def apply_changes
	
	def set_client_proxy(self,status):
		
		if not self.proxy_var_initialized:
			#INIT VALUE
			self.client.add_variable(self.key,"VariablesManager","CLIENT_PROXY_ENABLED",status,"","Variable to enable or disable proxy in classroom clients",[])
			self.proxy_var_initialized=True
			return True
		
		self.client.set_variable(self.key,"VariablesManager","CLIENT_PROXY_ENABLED",status)
		
	#def set_client_proxy
	
	def routing_changed(self,widget):
		
		if self.routing_enabled_rbutton.get_active() and self.nat_enabled_rbutton.get_active():
			self.proxy_frame.set_sensitive(True)
		else:
			self.proxy_frame.set_sensitive(False)
		
	#def routing_changed
	
	def close_window(self,widget):
		
		Gtk.main_quit()
		sys.exit(0)
		
	#def close_window
	
	
#class NatManager

def usage():
	print("USAGE:")
	print("\tnat-manager [ -ip TEMPLATE_FILE -u USER -p PASSWORD ]")

if __name__=="__main__":
	
	nm=NatManager()
	
