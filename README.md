# VulnTrack #
Beta Release

Pulls the NIST vulnerability feed regularly and matches it against your config file. 
Matched vulnerabilities alert by desktop popup and/or email.

Potential uses include: 
* Being notified when new vulnerabilities come up in network appliances and other things that might not fall into your normal patch management.
* Profile a target on a pentest and create a group in the config file based on that.  If vulnerabilities come up during the engagement it will notify you.
* Being notified about vulnerabilities in web applications.
	
Included Files:
* vulnget.py: Grabs the latest vulnerabilities from the NIST rss feed.  This should run as a cron job
* vulntrack-gtk.py: GUI frontend and tray applet.  Also periodically checks for new vulnerabilities and alerts ones you haven't seen yet.
* vulns.db: Class for working with the database
* vulnalert.py: Class for sending alerts
* config.xml: Config file
	
How to use:
* mkdir /opt/vulntrack
* cd /opt/vulntrack
* git clone https://github.com/Ogma/VulnTrack
* Edit config.xml to suit your needs
* Run /opt/vulntrack/vulnget.py once to populate your database initially
* run crontab -e and add (to make it check for vulnerabilities hourly): 0 * * * *  /opt/vulntrack/vulnget.py
* Run /opt/vulntrack/vulntrack-gtk to get the interface.  Note: When you close the window it stays alive in the tray.  Right click the tray icon and select Exit exit the program.
	

A few things to note:
* This is an early beta release, much work to be done and lots of bugs to be fixed.
* There is still functionality missing
* Acknowledge acknowledges you've seen the vulnerability and it won't show up anymore, however it still is in the database.
* Remove deletes the vulnerability from the database.
* I'll have an install script thrown together soon
