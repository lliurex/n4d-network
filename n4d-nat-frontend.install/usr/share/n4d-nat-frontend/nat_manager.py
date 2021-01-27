import gi
gi.require_version('Gtk','3.0')

from gi.repository import Gtk, Gdk,GdkPixbuf,GObject,GLib

import n4d.client
import sys
import os
import os.path

import signal

signal.signal(signal.SIGINT, signal.SIG_DFL)

import gettext
gettext.textdomain('n4d-nat-frontend')
_ = gettext.gettext

MARGIN=20

class NatManager:
	
	def __init__(self,ip="localhost"):
		
		status=self.read_key()
		self.status_error=None
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
#		self.client=xmlrpclib.ServerProxy("https://"+ip+":9779")
		self.n4dclient=n4d.client.Client("https://%s:9779"%ip)
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
		
	#		try:
			
			ret = self.n4dclient.get_nat("","NetworkManager")
			self.status["nat"] = ret
			ret = self.n4dclient.get_routing("","NetworkManager")
			self.status["routing"] = ret
			self.status["nat_persistence"] = True
			self.status["routing_persistence"] = True
			try:
				proxy_status = self.n4dclient.get_variable("CLIENT_PROXY_ENABLED")
			except n4d.client.CallFailedError as e:
				if e.code==-5:
					proxy_status=None
			try:
				self.external_interface = self.n4dclient.get_variable("EXTERNAL_INTERFACE")
			except n4d.client.CallFailedError as e:
				if e.code==-5:
					self.external_interface=None
			if proxy_status == None:
				self.proxy_var_initialized = False
				proxy_status = True
			else:
				self.proxy_var_initialized = True
			self.status["proxy"] = proxy_status
			
	#	except Exception as e:
	#		print("ERROR: %s"%e)
	#		self.status_error=_("N4D error: ") + str(e)
			#set msg error
		
	#def get_status_list

	
	def build_gui(self):
		
		self._set_css_info()
		
		'''
		
		# THERE WAS AN OLD GUI WAS HERE. 
		# IT'S GONE NOW
		
		builder=Gtk.Builder()
		builder.set_translation_domain('n4d-nat-frontend')
		if os.path.exists("/srv/svn/pandora/n4d-network/trunk/n4d-nat-frontend.install/usr/share/n4d-nat-frontend/rsrc/nat-manager.glade"):
			builder.add_from_file("/srv/svn/pandora/n4d-network/trunk/n4d-nat-frontend.install/usr/share/n4d-nat-frontend/rsrc/nat-manager.glade")
		else:
			builder.add_from_file("/usr/share/n4d-nat-frontend/rsrc/nat-manager.ui")
		'''
		
		self.window=Gtk.Window()
		main_vbox=Gtk.VBox()
		main_vbox.set_halign(Gtk.Align.FILL)
		
		
		
		vbox=Gtk.VBox()
		vbox.set_halign(Gtk.Align.FILL)
		vbox.set_margin_bottom(MARGIN)
		vbox.set_margin_left(MARGIN)
		vbox.set_margin_right(MARGIN)

		pb=GdkPixbuf.Pixbuf.new_from_file("/usr/share/n4d-nat-frontend/rsrc/nat-manager.png")
		img_banner=Gtk.Image.new_from_pixbuf(pb)
		img_banner.props.halign=Gtk.Align.CENTER
		img_banner.set_margin_top(0)
		img_banner.set_margin_bottom(MARGIN)
		main_vbox.pack_start(img_banner,False,False,0)

		boxrou=Gtk.VBox()
		lblrou=Gtk.Label()
		lblrou.set_markup('<span size="medium">%s</span>'%_("Routing status"))
		boxrou.add(lblrou)
		self.lblrou_info=Gtk.Label()
		lblrou.props.halign=Gtk.Align.START
		self.lblrou_info.props.halign=Gtk.Align.START
		self.lblrou_info.set_markup('<span size="small" color="grey">%s</span>'%_("Route traffic through server"))
		boxrou.add(self.lblrou_info)
		boxrou.props.halign=Gtk.Align.START

		self.swtrou=Gtk.Switch()
		self.swtrou.props.halign=Gtk.Align.END
		self.swtrou.set_active(self.status["routing"])

		tmp_hbox=Gtk.HBox()
		tmp_hbox.pack_start(boxrou,False,False,0)
		tmp_hbox.pack_end(self.swtrou,False,False,0)
		vbox.pack_start(tmp_hbox,True,True,0)
		vbox.pack_start(Gtk.Separator(),True,True,3)


		boxnat=Gtk.VBox()
		lblnat=Gtk.Label()
		lblnat.set_markup('<span size="medium">%s</span>'%_("NAT status"))
		lblnat.props.halign=Gtk.Align.START
		boxnat.add(lblnat)
		self.lblnat_info=Gtk.Label()
		self.lblnat_info.props.halign=Gtk.Align.START
		self.lblnat_info.set_markup('<span size="small" color="grey">%s</span>'%_("Redirect server ports to client ports"))
		boxnat.add(self.lblnat_info)
		boxnat.props.halign=Gtk.Align.START
		self.swtnat=Gtk.Switch()
		self.swtnat.props.halign=Gtk.Align.END
		self.swtnat.set_active(self.status["nat"])
		

		tmp_hbox=Gtk.HBox()
		tmp_hbox.pack_start(boxnat,False,False,0)
		tmp_hbox.pack_end(self.swtnat,False,False,0)
		vbox.pack_start(tmp_hbox,True,True,3)
		vbox.pack_start(Gtk.Separator(),True,True,3)

		boxpro=Gtk.VBox()
		lblpro=Gtk.Label()
		lblpro.props.halign=Gtk.Align.START
		lblpro.set_markup('<span size="medium">%s</span>'%_("Proxy status"))
		boxpro.add(lblpro)
		self.lblpro_info=Gtk.Label()
		self.lblpro_info.props.halign=Gtk.Align.START
		self.lblpro_info.set_markup('<span size="small" color="grey">%s</span>'%_("Enable proxy in classroom clients"))
		boxpro.add(self.lblpro_info)
		self.swtpro=Gtk.Switch()
		self.swtpro.props.halign=Gtk.Align.END
		self.swtpro.set_active(self.status["proxy"])

		
		tmp_hbox=Gtk.HBox()
		tmp_hbox.pack_start(boxpro,False,False,0)
		tmp_hbox.pack_end(self.swtpro,False,False,0)
		vbox.pack_start(tmp_hbox,True,True,3)
		
		self.msg_label=Gtk.Label()
		vbox.pack_start(self.msg_label,True,True,10)

		self.swtnat.connect("state-set",self.routing_changed)
		self.swtrou.connect("state-set",self.routing_changed)
		self.swtpro.connect("state-set",self.routing_changed)
		
		if not self.status["nat"] or not self.status["routing"]:
			self.swtpro.set_sensitive(False)

		main_vbox.pack_start(vbox,True,True,0)
		self.window.add(main_vbox)
		self.window.resize(450,250)
		self.window.set_resizable(False)
		self.window.set_position(Gtk.WindowPosition.CENTER)
		self.window.show_all()
		self.window.connect("destroy",Gtk.main_quit)

		if self.status_error!=None:
			self.msg_label.set_markup("<span foreground='red'>"+self.status_error+"</span>")
		else:
			self.msg_label.hide()

		Gtk.main()
		
	#def build_gui
	
	def routing_changed(self,*args):
		widget=args[0]
		state=args[-1]
		if widget==self.swtrou:
			print("Routing change %s"%state)
			self.n4dclient.set_routing(self.key,"NetworkManager",state,self.status["routing_persistence"])

		elif widget==self.swtnat:
			print("NAT change %s"%state)
			self.n4dclient.set_nat(self.key, "NetworkManager", state,self.status["nat_persistence"], self.external_interface)
		elif widget==self.swtpro:
			self.set_client_proxy(state)

		if self.swtrou.get_active() and self.swtnat.get_active():
			self.swtpro.set_sensitive(True)
		else:
#			self.set_client_proxy(True)
#			self.lblpro_info.set_markup('<span size="small" color="grey">%s</span>'%_("Actual state is enabled"))
			self.swtpro.set_sensitive(False)
			self.swtpro.set_state(True)
	#def routing_changed
	
	def set_client_proxy(self,state):
		print("Proxy change %s"%state)
		
		if not self.proxy_var_initialized:
			#INIT VALUE
			self.n4dclient.add_variable(self.key,"VariablesManager","CLIENT_PROXY_ENABLED",state,"","Variable to enable or disable proxy in classroom clients",[])
			self.proxy_var_initialized=True
			return True
		
		self.n4dclient.set_variable(self.key,"VariablesManager","CLIENT_PROXY_ENABLED",state)
		
	#def set_client_proxy
	
	def close_window(self,widget):
		Gtk.main_quit()
		sys.exit(0)
	#def close_window
	
	def _set_css_info(self):
	
		css = b"""

		GtkEntry{
			font-family: Roboto;
			border:0px;
			border-bottom:1px grey solid;
			margin-top:0px;
			padding-top:0px;
		}
		GtkGrid{
			background: red;
		}

		GtkLabel {
			font-family: Roboto;
		}

		#NOTIF_LABEL{
			background-color: #3366cc;
			font: 11px Roboto;
			color:white;
			border: dashed 1px silver;
			padding:6px;
		}

		#ERROR_LABEL{
			background-color: red;
			font: 11px Roboto;
			color:white;
			border: dashed 1px silver;
			padding:6px;
		}

		#ENTRY_LABEL{
			color:grey;
			padding:6px;
			padding-bottom:0px;
		}

		#PLAIN_BTN,#PLAIN_BTN:active{
			border:0px;
			padding:0px;
			background:white;
		}
		
		#PLAIN_BTN_DISABLED,#PLAIN_BTN_DISABLED:active{
			border:0px;
			padding:0px;
			background:white;
			color:grey;
		}

		#COMPONENT{
			padding:3px;
			border: dashed 1px silver;

		}

		#WHITE_BACKGROUND {
			background-color:rgba(255,255,255,1);
		
		}

		#BLUE_FONT {
			color: #3366cc;
			font: 11px Roboto Bold;
			
		}	
		

		#TASKGRID_FONT {
			color: #3366cc;
			font: 11px Roboto;
			
		}

		#LABEL #LABEL_INSTALL{
			padding: 6px;
			margin:6px;
			font: 12px Roboto;
		}

		#LABEL_OPTION{
		
			font: 48px Roboto;
			padding: 6px;
			margin:6px;
			font-weight:bold;
		}

		#ERROR_FONT {
			color: #CC0000;
			font: 11px Roboto Bold; 
		}

		#MENUITEM {
			padding: 12px;
			margin:6px;
			font: 24px Roboto;
			background:white;
		}

		#BLUEBUTTON {
			background-color: #3366cc;
			color:white;
			font: 11px Roboto Bold;
		}

		"""
		self.style_provider=Gtk.CssProvider()
		self.style_provider.load_from_data(css)
		Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(),self.style_provider,Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
	#def set_css_info	
	
#class NatManager

def usage():
	print("USAGE:")
	print("\tnat-manager [ -ip TEMPLATE_FILE -u USER -p PASSWORD ]")

if __name__=="__main__":
	
	nm=NatManager()
	
