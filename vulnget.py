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
import xml.etree.ElementTree as ET
import httplib
import re
import sys
import os
import sqlite3
import vulndb


config = ET.parse('config.xml')
config_root = config.getroot()



########################################################################
#							FEED STUFF									
########################################################################

# Function to grab the NIST Vuln feed in XML format
def getFeed():
    conn = httplib.HTTPSConnection("nvd.nist.gov")
    conn.request("GET", "/download/nvd-rss.xml")
    re = conn.getresponse()

    return re.read()

def fileFeed():
	f = open("nvd-rss.xml", "r")
	return f.read()

# Create a python ojbect with the data we need
class Vuln:
    def __init__(self):
        feed = getFeed()
        root = ET.fromstring(feed)
        for vuln in root:
            self.cve = vuln[0].text
            self.link = vuln[1].text
            self.desc = vuln[2].text
            self.date = vuln[2].text



########################################################################
#							VULN L-LIST									
#				Makes it easier to work with the data
########################################################################

class Vuln(object):
    def __init__(self, data=None, next_node=None):
        self.data = data
        self.next_node = next_node

    def get_data(self):
        return self.data

    def get_next(self):
        return self.next_node

    def set_next(self, new_next):
        self.next_node = new_next

class VulnList(object):
    def __init__(self, head=None):
        self.head = head

    def insert(self,data):
        new_vuln = Vuln(data)
        new_vuln.set_next(self.head)
        self.head = new_vuln

    def search(self, data, terms, group="Default", DataBase=None):
		current = self.head
		r = re.compile(data, re.IGNORECASE)
		while current:
			if r.search(current.data[2]):
				# If we are going to add the object to a list of matched vulnerabilities
				if DataBase: 
					# Adding to the list of Matched Vulnerabilities
					print "%s matched based on %s." % (current.data[0], terms)
					DataBase.insert(current.data, group, terms)
				else: # Otherwise just print it out (for debugging and testing purposes
						print "CVE:", current.data[0] 
						print "Link:", current.data[1] 
						print "Description:", current.data[2]
						print "Date:", current.data[3]
						print "========================================="

			current = current.get_next()

    def walk(self, callback=None):
        current = self.head
        while current:
			if(callback == None):
				# Print matched vulnerabilities to the screen
				print current.data[0] # CVE
				print current.data[1] # Link
				print current.data[2] # Description
				print current.data[3] # date
			else:
				callback(current)
            
			current = current.get_next()

########################################################################
#							MAIN FUNCTION								
########################################################################

if __name__ == "__main__":
    if len(sys.argv) > 1:
        search = sys.argv[1]
    else:
        search = "CSRF"
    
    # Initialize database...
    db = vulndb.db()
	# create a list to hold the entire feed
    Vulns = VulnList()
    # create a list to hold matched vulnerabilities GOING AWAY????
    MatchedVulns = VulnList()
    # get nist feed and set xml root
    #feed = getFeed()
    feed = getFeed()
    root = ET.fromstring(feed)

    for i in root:
        info = []
        info.append(i[0].text) # CVE
        info.append(i[1].text) # Link
        info.append(i[2].text) # description
        info.append(i[3].text) # date
        # Add to the list of Vulns
        Vulns.insert(info)

    #Vulns.search(search)
    for group in config_root.findall('group'):
		for term in group.findall('term'):
			searchstring = "(?=.*" + term.get('value') + ")"
			searchterms = term.get('value')
			condition_and = term.get('and')
			if condition_and:
				searchstring += "(?=.*" + condition_and + ")"
				searchterms += " and " + condition_and
				
			if len(term._children) > 0:
				for ex in term.findall('exclude'):
					searchstring += "(?!.*" + ex.text + ")^.*$"
					searchterms += " excluding" + ex.text
					
			Vulns.search(searchstring, searchterms, group.get("value"), db)

    MatchedVulns.walk()
    
    
