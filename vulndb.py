#!/usr/bin/python
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
				acknowledged				int not null,
				terms			text not null,
				alert			int not null,
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
				primary key(vulns_id, groups_id));""")
		else:
			self.conn = sqlite3.connect(self.dbfile)
	
	# Insert vulnerability entry into database
	def insert(self, vulnitem, group, searchterms):
		cursor = self.conn.cursor()
		cursor.execute("""
		insert or ignore into vulns(cve, link, description, date, acknowledged, terms, alert) 
		values( :cve, :link, :description, :date,0, :terms, 0);""", 
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
		cursor.execute("""insert or ignore into vulns_has_groups(vulns_id, groups_id) values(:vuln, :group);""",(vuln_id,group_id))
		self.conn.commit()

	# Save changes to database
	def commit(self):
		self.conn.commit()

	# Retrieve information 
	def select(self):
		cursor = self.conn.cursor()
		cursor.execute("""select vulns.*, groups.name as group_name from vulns, vulns_has_groups, groups
						where vulns.id = vulns_has_groups.vulns_id
						and groups.id = vulns_has_groups.groups_id
						and vulns.acknowledged = 0""")
		return cursor.fetchall()
	
	# Get the number of vulnerabilities that haven't been alerted yet
	def count(self):
		cursor = self.conn.cursor()
		cursor.execute("""select count(*) from vulns, vulns_has_groups, groups
						where vulns.id = vulns_has_groups.vulns_id
						and groups.id = vulns_has_groups.groups_id
						and vulns.alert = 0""")
		return cursor.fetchone()
	
	# Remove a vulnerability from the database
	# Needs to be fixed up since I added groups
	def remove(self, item):
		self.conn.execute("""delete from vulns where id= :id""", (item,))
		self.conn.commit()
	
	# Acknowledge a vulnerability so it won't show up in the window anymore
	# Needs to be fixed up since I added groups
	def acknowledge(self, item):
		self.conn.execute("""update vulns set acknowledged=1 where id= :id""",(item,))
		self.conn.commit()
	
	def togglealert(self):
		self.conn.execute("update vulns set alert=1 where alert=0")
		self.conn.commit()

