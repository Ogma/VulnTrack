#!/usr/bin/python
import vulndb
import smtplib
import xml.etree.ElementTree as ET
import dbus

class alert:
	def __init__(self):
		# Read config file to get alerting options
		config = ET.parse('config.xml')
		root = config.getroot()
		for options in root.findall('options'):
				for opt in options:
					if opt.tag == 'email':
						if opt.get('enabled') == 'True':
							self.email = True
						else:
							self.email = False
						self.mailserver = opt.find('server').text
						self.mailuser = opt.find('username').text
						self.mailpass = opt.find('password').text
						self.mailrecv = opt.find('recipient').text
						self.mailfrom = opt.find('from').text
						self.mailport = opt.find('port').text
					elif opt.tag == 'log':
						self.logfile = opt.get('file')
					elif opt.tag == 'popup':
						if opt.get('enabled') == 'True':
							self.popup = True
						else:
							self.popup = False
						

	########################################################################
	#							EMAIL ALERT									
	########################################################################
	def sendEmail(self, data):
		if self.email:
			# Build email message html from data
			msgdata = "<h1>VulnTrack - New Vulnerabilities</h1>"
			msgdata += "<table border='1'>"
			msgdata += "<tr style='background-color:#ccc;'><td><strong>Date</strong></td><td><strong>CVE</strong></td><td><strong>Terms</strong></td>"
			msgdata += "<td><strong>Group</strong></td><td><strong>Description</strong></td><td><strong>Link</strong></td></tr>"
			for row in data:
				msgdata += "<tr>"
				date = row[4].split('T')[0].split('-')
				date = date[1] + "-" + date[2] + "-" + date[0]
				msgdata += "<td>" + date + "</td>"		# Date
				msgdata += "<td>" + row[1][:14] + "</td>"	#CVE 
				msgdata += "<td>" + row[6] + "</td>"	#Terms
				msgdata += "<td>" + row[8] + "</td>"	#Group
				msgdata += "<td>" + row[3] + "</td>"	#Description
				msgdata += "<td> <a href=\"" + row[2] + "\">Link</a></td>"	#Link
				msgdata += "</tr>"
			msgdata += "<table>"
			
			msg = "\r\n".join([
				"From: " + self.mailfrom,
				"To: " + self.mailrecv,
				"MIME-Version: 1.0",
				"Content-type: text/html",
				"Subject: New Vulnerabilities",
				"", msgdata])

			server = smtplib.SMTP(self.mailserver +":"+ self.mailport)
			server.ehlo()
			server.starttls()
			server.login(self.mailuser,self.mailpass)
			server.sendmail(self.mailfrom, self.mailrecv, msg)
			server.quit()

	########################################################################
	#							POPUP ALERT									
	########################################################################
	def popupNotify(self, title, text):
		if self.popup:
			item = "org.freedesktop.Notifications"
			path = "/org/freedesktop/Notifications"
			interface = "org.freedesktop.Notifications"
			app_name = "VulnTrack"
			id_num_to_replace = 0
			icon = "alert.png"
			actions_list = ''
			hint = ''
			time = 0   # Use seconds x 1000

			bus = dbus.SessionBus()
			notif = bus.get_object(item, path)
			notify = dbus.Interface(notif, interface)
			notify.Notify(app_name, id_num_to_replace, icon, title, text, actions_list, hint, time)
