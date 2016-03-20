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
#	VulnTrack database class
########################################################################

import sqlite3
import os

class db(object):
	dbfile = "vulns.db"

	# Connect to databse, if it doesn't exist create it
	def __init__(self):
		if not os.path.exists(self.dbfile):
			print "Creating database"
			self.conn = sqlite3.connect(self.dbfile)
			self.conn.execute("""
			create table vulns (
				id					integer primary key autoincrement not null,
				cve				text not null,
				link				text not null,
				description		text not null,
				date				text not null,
				terms			text not null,
				constraint cve_unique unique(cve));""")
			self.conn.execute("""
			create table groups (
				id					integer primary key autoincrement not null,
				name				text not null,
				constraint group_unique unique(name));""")
			self.conn.execute("""
			create table vulns_has_groups (
				vulns_id			integer not null,
				groups_id			integer not null,
				alert				integer not null,
				acknowledged		integer not null,
				primary key(vulns_id, groups_id));""")
		else:
			self.conn = sqlite3.connect(self.dbfile)
	
	# Insert vulnerability entry into database
	def insert(self, vulnitem, group, searchterms):
		cursor = self.conn.cursor()
		cursor.execute("""
		insert or ignore into vulns(cve, link, description, date, terms) 
		values( :cve, :link, :description, :date, :terms);""", 
		[vulnitem[0], vulnitem[1], vulnitem[2],vulnitem[3], searchterms])
		# Retrieve vuln id  from the vulns table
		cursor.execute("""select id from vulns where cve = :cve;""", (vulnitem[0], ))
		vuln_id = cursor.fetchone()[0]
		
		# Check to see if group already exists in database
		cursor.execute("""select * from groups where name = :name;""", (group,))
		group_entry = cursor.fetchone()
		if group_entry:
			group_id = group_entry[0]
		else:
			cursor.execute("""insert into groups(name) values( :group );""", (group,))
			group_id = cursor.lastrowid
		# populate the vulns has group table
		cursor.execute("""insert or ignore into vulns_has_groups(vulns_id, groups_id, alert, acknowledged) values(:vuln, :group, 0, 0);""",(vuln_id,group_id))
		self.conn.commit()

	# Save changes to database
	def commit(self):
		self.conn.commit()

	# Retrieve information 
	def select(self):
		cursor = self.conn.cursor()
		cursor.execute("""select vulns.id, vulns.cve, vulns.link, vulns.description, vulns.date, vulns_has_groups.acknowledged, 
		vulns.terms, vulns_has_groups.alert, groups.name as group_name from vulns, vulns_has_groups, groups where 
		vulns.id = vulns_has_groups.vulns_id and groups.id = vulns_has_groups.groups_id and vulns_has_groups.acknowledged = 0;""")
		return cursor.fetchall()
	
	# Get the number of vulnerabilities that haven't been alerted yet
	def count(self):
		cursor = self.conn.cursor()
		cursor.execute("""select count(*) from vulns, vulns_has_groups, groups
						where vulns.id = vulns_has_groups.vulns_id
						and groups.id = vulns_has_groups.groups_id
						and vulns_has_groups.alert = 0""")
		return cursor.fetchone()
	
	# Remove a vulnerability from the database
	def remove(self, item, group=None):
		if group is None: # Remove all instances of the vulnerability
			self.conn.execute("""delete from vulns where id= :id""", (item,))
			self.conn.execute("""delete from vulns_has_groups where vulns_id= :id""", (item,))
		else: # only remove the CVE from that group
			self.conn.execute("""delete from vulns_has_groups where
			vulns_id= :id and 
			vulns_has_groups.groups_id = (select id from groups where groups.name = :group)""", (item, group));
		self.conn.commit()
	
	# Acknowledge a vulnerability so it won't show up in the window anymore
	# This functionality will be expanded upon later to make it more useful
	def acknowledge(self, item, group=None):
		if group is None:
			self.conn.execute("""update vulns_has_groups set acknowledged=1 where vulns_id= :id""",(item,))
		else:
			self.conn.execute("""update vulns_has_groups set acknowledged=1 where
			vulns_id= :id and
			vulns_has_groups.groups_id = (select id from groups where groups.name = :group)""", (item, group));
		self.conn.commit()
	
	def togglealert(self):
		self.conn.execute("update vulns_has_groups set alert=1 where alert=0")
		self.conn.commit()

