#!/usr/bin/python
#VulnTrack by Ogma
#License: GPL
#            .__       .___.__                     
#  __________ |  |    __| _/|__| ______________  ___
# /  ___/  _ \|  |   / __ | |  |/ __ \_  __ \  \/  /
# \___ (  <_> )  |__/ /_/ | |  \  ___/|  | \/>    < 
#/____  >____/|____/\____ | |__|\___  >__|  /__/\_ \
#     \/                 \/         \/            \/
#				www.soldierx.com
########################################################################
#	VulnTrack GTK Gui and Tray Applet
########################################################################

import pygtk
pygtk.require('2.0')
import gtk
import webbrowser
import vulndb
import glib
import vulnalert


########################################################################
#							TRAY APPLET
#				also controls polling and alerting						
########################################################################

class TrayApplet:
	def __init__(self):
		icon = gtk.status_icon_new_from_file("icon.png")
		icon.connect('popup-menu', self.rightClick)
		icon.connect('activate', self.leftClick)
		self.window = NistWindow()
		self.checkfornew()
		#start timer to check the database again for new vulns every 10 min
		glib.timeout_add_seconds(600, self.checkfornew)
	
	def checkfornew(self):
		db = vulndb.db()
		count = db.count()[0]
		if count > 0:
			alert = vulnalert.alert()
			# the alert class will decide to alert or not based on the config file
			alert.popupNotify("New vulnerabilities", "There are " + str(count) + " new vulnerabilities")
			alert.sendEmail(db.select())
			# toggle the alert field for those vulns
			db.togglealert()
			# update window with new items
			self.window.refreshlist()
		return True
		
	 
	def openWindow(self, data=None):
		if self.window:
			self.window.show_window()
			
	 
	def exitApp(self, data=None):
		gtk.main_quit()
	 
	def createMenu(self, event_button, event_time, data=None):
		menu = gtk.Menu()
		open_item = gtk.MenuItem("Open window")
		close_item = gtk.MenuItem("Exit")
	  
		# Menu items
		menu.append(open_item)
		menu.append(close_item)
		open_item.connect_object("activate", self.openWindow, "Open")
		close_item.connect_object("activate", self.exitApp, "Exit")
		open_item.show()
		close_item.show()
	  
		#Popup the menu
		menu.popup(None, None, None, event_button, event_time)
	 
	def rightClick(self, ata, event_button, event_time):
		self.createMenu(event_button, event_time)
	 
	def leftClick(self, event):
		if self.window:
			self.window.show_window()
			
########################################################################
#							WINDOW									
########################################################################

class NistWindow:
	def __init__(self):
		# database connection
		self.db = vulndb.db()
		
		self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
		self.window.set_title("Vulnerabilities")
		self.window.set_size_request(800, 600)
		self.window.set_border_width(10)
		self.window.set_position(gtk.WIN_POS_CENTER_ALWAYS)
		self.window.connect("delete-event", self.destroy)
		self.window.set_icon_from_file("icon.png")
		
		# Window Boxes
		main_vbox = gtk.VBox(False, 3)
		top_hbox = gtk.HBox()
		
		
		################################################################
		#			Top Part of Window
		################################################################

		# Variable to keep track of the database index for each item
		self.dbindex = ""
		link_click = gtk.EventBox()
		self.lbl_cve = gtk.Label()
		
		self.lbl_cve.set_alignment(0,0)
		self.lbl_date = gtk.Label()
		self.lbl_date.set_alignment(0,0)
		self.lbl_desc = gtk.Label()
		self.lbl_desc.set_line_wrap(True)
		self.lbl_desc.set_justify(gtk.JUSTIFY_LEFT)
		self.lbl_desc.set_size_request(500,60)
		self.lbl_desc.set_alignment(0,0)
		self.lbl_link = gtk.Label() 
		self.lbl_link.set_alignment(0,0)
		self.lbl_link.grab_focus()
		
		link_click.add(self.lbl_link)
		link_click.connect("button_press_event", self.openlink)

		
		top_halign = gtk.Alignment(1, 0, 0, 0)
		top_vbox = gtk.VBox()
		
		# Link button requires a uri to start with, might as well go with SX
		self.linkbutton1 = gtk.LinkButton("http://www.soldierx.com")
		self.linkbutton1.set_alignment(0,0)
		self.linktt = gtk.Tooltips()
		
		
		btnAck = gtk.Button("Acknowlege")
		btnRemove = gtk.Button("Remove")
		tt_btnAck = gtk.Tooltips()
		tt_btnRemove = gtk.Tooltips()
		
		tt_btnAck.set_tip(btnAck, "Don't show vulnerability in list anymore\nStays in database though")
		tt_btnRemove.set_tip(btnRemove, "Remove vulnerability from database\nYour config file may result in this vulnerability being added again")
		
		action_btn_box = gtk.HButtonBox()
		action_btn_box.set_layout(gtk.BUTTONBOX_SPREAD)
		action_btn_box.set_spacing(20)
		action_btn_box.add(btnAck)
		action_btn_box.add(btnRemove)
		right_frame = gtk.Frame("Actions")
		right_frame.set_size_request(250,100)
		right_frame.add(action_btn_box)
		
		top_vbox.pack_start(self.lbl_cve, padding=2)
		top_vbox.pack_start(self.lbl_date, padding=2)
		top_vbox.pack_start(self.lbl_desc, padding=2)
		top_vbox.pack_start(self.linkbutton1, padding=2)
		
		top_hbox.pack_start(top_vbox)
		top_hbox.pack_start(top_halign)
		top_hbox.pack_start(right_frame, False, False, 20)
		
		
		
		main_vbox.pack_start(top_hbox, False, False, 10)

		################################################################
		#			Treeview part of window
		################################################################
		
		# Make the main window scrollable
		swindow = gtk.ScrolledWindow()
		swindow.set_shadow_type(gtk.SHADOW_ETCHED_IN)
		swindow.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
		
		# Put scollable window in the VBox
		main_vbox.pack_start(swindow, True, True, 0)
		
		# Create Model for list store
		self.store = self.list_model()
		self.treeview = gtk.TreeView(self.store)
		self.treeview.set_rules_hint(True)
		
		# Create the columns 
		self.create_columns(self.treeview)
		
		select = self.treeview.get_selection()
		select.connect("changed", self.row_selected)
		
		btnAck.connect("clicked", self.action, self.treeview, "acknowledge")
		btnRemove.connect("clicked", self.action, self.treeview, "remove")
		# Add treeview to scrollable window
		swindow.add(self.treeview)
		
		self.window.add(main_vbox)
		
		# Show window
		self.window.show_all()
		
		# Select the first item on the list
		self.treeview.grab_focus()
		select.select_path(0)
	
	def show_window(self):
		self.window.show_all()
		
	# Create list model 
	def list_model(self):
		# Pulling data from database and adding to list
		store = gtk.ListStore(str, str, str, str, str,str, str)
		for row in self.db.select():
			# Ghetto formatting to Murican dates
			date = row[4].split('T')[0].split('-')
			date = date[1] + "-" + date[2] + "-" + date[0]
						#id       date  cve     terms    group   description link
			store.append([row[0], date, row[1][:14], row[6], row[8], row[3], row[2]])
		return store
		
	# Create columns for the treeview
	def create_columns(self, treeView):
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("ID", rendererText, text=0)
		column.set_sort_column_id(0) 
		column.set_max_width(1)   
		treeView.append_column(column)
		
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("Date", rendererText, text=1)
		# the logical column ID of the model to sort
		column.set_sort_column_id(1)
		# append the column
		treeView.append_column(column)

		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("CVE", rendererText, text=2)
		column.set_sort_column_id(2)
		column.set_resizable(True)
		column.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
		column.set_min_width(120)    
		treeView.append_column(column)
		
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("Terms", rendererText, text=3)
		column.set_resizable(True)
		column.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
		column.set_min_width(80)
		column.set_sort_column_id(3)
		treeView.append_column(column)
		
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("Group", rendererText, text=4)
		column.set_resizable(True)
		column.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
		column.set_min_width(110)
		column.set_sort_column_id(4)
		treeView.append_column(column)
		
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("Description", rendererText, text=5)
		column.set_resizable(True)
		column.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
		column.set_min_width(370)
		column.set_sort_column_id(5)    
		treeView.append_column(column)
		
		rendererText = gtk.CellRendererText()
		column = gtk.TreeViewColumn("Link", rendererText, text=6)
		column.set_sort_column_id(6)
		column.set_visible(False)
		treeView.append_column(column)
	
	def refreshlist(self):
		self.store.clear()
		self.store = self.list_model()
		self.treeview.set_model(self.store)
	
	def row_selected(self, selection):
		model, treeiter = selection.get_selected()
		if treeiter != None:
			 # Update top portion of window
			 self.lbl_cve.set_markup("<b><u>" + model[treeiter][2] + "</u></b>")
			 self.lbl_date.set_text(model[treeiter][1])
			 self.lbl_desc.set_text(model[treeiter][5])
			 self.linkbutton1.set_label(model[treeiter][6])
			 self.linktt.set_tip(self.linkbutton1, model[treeiter][6])
			 self.linkbutton1.set_uri(model[treeiter][6])
			 self.dbindex = model[treeiter][0]
			 self.vulngroup = model[treeiter][4]

	
	def action(self, widget, treeview, action):
		msg = """Apply to all instances of this CVE across all groups?"""
		messagedialog = gtk.MessageDialog(parent=None, flags=0, type=gtk.MESSAGE_QUESTION, buttons=gtk.BUTTONS_OK, message_format=msg)

		dialogarea = messagedialog.get_content_area()
		msghbox = gtk.HBox()
		chkaction = gtk.RadioButton(None,"Apply to all instances")
		chkaction_1 = gtk.RadioButton(chkaction,"Apply to only this instance")
		msghbox.pack_start(chkaction)
		msghbox.pack_start(chkaction_1)
		
		dialogarea.pack_start(msghbox)
		messagedialog.show_all()
		messagedialog.run()
		
		if action == "acknowledge":
			if chkaction.get_active():
				self.db.acknowledge(self.dbindex) # Acknowledge all instances
			else:
				self.db.acknowledge(self.dbindex, self.vulngroup) # Acknowledge only this instance
		elif action == "remove":
			if chkaction.get_active():
				self.db.remove(self.dbindex) # Remove all instances
			else:
				self.db.remove(self.dbindex, self.vulngroup) # Remove only this instance.
			
		
		selection = treeview.get_selection()
		result = selection.get_selected()
		path = selection.get_selected_rows()

		if result:
			model, iter = result
		
		model.remove(iter)
		treeview.grab_focus()
		selection.select_path( path[1][0][0] )

		messagedialog.destroy()
	
	# Open lin in browser
	def openlink(self, widget, event):
		print widget.child.get_text()
		webbrowser.open(widget.child.get_text())
	
	# Close the program
	def destroy(self, widget, bla):
		#gtk.main_quit()
		self.window.hide()
		return True
		
	# Required by GTK
	def main(self):
		gtk.main()

if __name__ == '__main__':
  applet = TrayApplet()
  gtk.main()
