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
import os
import sys
import platform
import subprocess

# is user root?
if not os.geteuid() == 0:
	sys.exit("Please run script as root")

if not platform.system() == "Linux":
	print "!! This tool hasn't been tested on %s yet !!" % platform.system()
	c = raw_input("Continue? (y/n)")
	if len(c) != 0:
		if c[0] is not 'y' or c[0] is not 'Y':
			sys.exit("!! Hopefully there will be a %s version available soon !!" % platform.system())

if len(sys.argv) > 1:
	if sys.argv[1] == "install":
		# We are installing
		install_files = ["vulntrack-gtk.py", "vulnget.py", "vulndb.py", 
						"vulnalert.py", "config.xml", "icon.png", "alert.png"]
		
		if not os.path.isdir("/opt/vulntrack"):
			print "** Creating install directory /opt/vulntrack **"
			subprocess.Popen("mkdir /opt/vulntrack", shell=True).wait()
			
		print "** Moving files to install directory **"
		
		for f in install_files:
			subprocess.Popen("cp " + f + " /opt/vulntrack/", shell=True).wait()
		
		print "** Setting permissions for vulntrack folder **"
		group = raw_input("Enter group (default is vulntrack):")
		if len(group) != 0:
			group = "vulntrack"
		subprocess.Popen("chgrp -R " + group + "/opt/vulntrack", shell=True).wait()
		subprocess.Popen("chmod -R 770 /opt/vulntrack", shell=True).wait()
		
		vulnget  = "#!/bin/bash\n"
		vulnget += "cd /opt/vulntrack &&\n"
		vulnget += "python /opt/vulntrack/vulnget.py"
		
		vulntrack  = "#!/bin/bash\n"
		vulntrack += "cd /opt/vulntrack &&\n"
		vulntrack += "python /opt/vulntrack/vulntrack-gtk.py"
		
		f = open("/usr/bin/vulnget", 'w')
		f.write(vulnget)
		f.close()
		
		f = open("/usr/bin/vulntrack-gtk", 'w')
		f.write(vulntrack)
		f.close()
		
		subprocess.Popen("chmod a+x /usr/bin/vulnget", shell=True).wait()
		subprocess.Popen("chmod a+x /usr/bin/vulntrack-gtk", shell=True).wait()
		
		print "** Creating cron job to monitor nist feed hourly **"
		cronfile = open("/etc/cron.hourly/vulnget.sh", 'w')
		cronfile.write(vulnget)
		cronfile.close() 
		subprocess.Popen("chmod a+x /etc/cron.hourly/vulnget.sh", shell=True).wait()
		
		
		print "** Install complete. **"
		print "Final steps:"
		print "\t Add user who will use vulntrack to the group:", group
		print "\t Login as that user and:"
		print "\t\t Edit /opt/vulntrack/config.xml to fit your needs"
		print "\t\t Run /usr/bin/vulnget to build the database for the first time"
		print "\t\t Run /usr/bin/vulntrack-gtk to view the GUI"
		
	if sys.argv[1] == "uninstall":
		print "** Uninstalling Vulntrack **"
		print "!! Warning uninstall will delete your config file and database. !!"
		c = raw_input("Continue? (y/n)")
		if len(c) != 0:
			if c[0] is 'y' or c[0] is 'Y':
				print "** Removing installed files **"	
				subprocess.Popen("rm /usr/bin/vulntrack-gtk", shell=True).wait()
				subprocess.Popen("rm /usr/bin/vulnget", shell=True).wait()
				subprocess.Popen("rm -rf /opt/vulntrack", shell=True).wait()
				subprocess.Popen("rm /etc/cron.hourly/vulnget.sh", shell=True).wait()
				print "** Done **"
			else:
				print "** Uninstall canceled **"
		else:
			print "** Uninstall canceled **"
		
else:
	print "run ./setup.py install to install"
