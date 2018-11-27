#!/usr/bin/python
"""
This script can remove unused users and corresponding network objects from Sophos UTM. If your UTM is flooded with thousands of ad users objects because of wrong initial setup - this is your help.

Warning!
	This code is based on undocumented functionality and not officially supported by Sophos. Use it on your own responsibility.
Warning!

"""

import json
import re
import sys
import subprocess
import csv,codecs,cStringIO
from datetime import datetime
import pprint
import logging

logfile = 'suuc.log'
logging.basicConfig(filename=logfile,level=logging.DEBUG,format='%(asctime)s PID=%(process)d %(funcName)s: %(message)s')

default_users = 'SophosUTMSupport system ha_sync anonymous admin'.split()
cc = 'confd-client.plx'


class UTMUsers:
	"""
	class UTMUsers represents Sophos UTM user management interface.
	"""
	def __init__(self):
		logging.info('Reading users from cc')
		sp_output = subprocess.check_output([cc, 'get_objects', 'aaa', 'user'])
        	users_json = cc_output_to_json(sp_output) 
#        	print(users_json)
        	self.users_list = json.loads(users_json, parse_int=str)
		logging.info('Done reading users from cc')

	def get_ref_by_name(self, name_str):
        	"""
        	return reference string of user with user[data][name] == name
        	"""
		user_dict = self.get_user_dict_by_name(name_str)
		if user_dict:
			return user_dict['ref']
		else:
			return None

	def get_name_by_ref(self, ref_str):
        	"""
        	return user name string of a user by object reference
        	"""
		user_dict = self.get_user_dict_by_ref(ref_str)
                if user_dict:
                        return user_dict['data']['name']
                else:
                        return None

		
	def get_user_dict_by_ref(self, ref_str):
        	"""
        	returns user dict by object reference string
        	"""
		target_users =  [user for user in self.users_list if user['ref'] == ref_str]
		if len(target_users) > 0:
			return target_users[0]
		else:
			logging.info('User with %s not found', ref_str)
			return None

	def user_exists(self, user_ref):
		return self.get_user_dict_by_ref(user_ref)	
	
	def username_exists(self, username):
		target_users =  [user for user in self.users_list if user['data']['name'] == username]
		if target_users:
			return True
		else:
			return False

	def get_user_dict_by_name(self, name_str):
        	"""
        	returns user dict by username string
        	"""
		target_users =  [user for user in self.users_list if user['data']['name'] == name_str]
		if len(target_users) > 0:
			return target_users[0]
		else:
			logging.info('User %s not found', name_str)
			return None


	def get_affected_nodes(self, ref_str):
		"""
		This function returns a list of node names or None affected by user represented with reference string
		"""
		if not ref_str:
			logging.info('Got None as ref_str')
			return
		sp_output = subprocess.check_output([cc, 'get_affected_nodes', ref_str])
        	affected_nodes_json = cc_output_to_json(sp_output) 
        	#print(affected_nodes_json)
        	affected_nodes_list = json.loads(affected_nodes_json)
		return  [node for sublist in affected_nodes_list for node in sublist]

	def get_affected_objects(self, ref_str):
		"""
		This function returns a list of object names or None affected by user represented with reference string
		"""
		if not ref_str:
			logging.info('Got None as ref_str')
			return
		sp_output = subprocess.check_output([cc, 'get_affected_objects', ref_str])
        	affected_objects_json = cc_output_to_json(sp_output) 
        	#print(affected_objects_json)
        	return json.loads(affected_objects_json)
	
	def get_user_network_ref(self, ref_str):
		"""
		Returns reference string of users network object
		"""
		user_dict = self.get_user_dict_by_ref(ref_str)
                if user_dict:
                        return user_dict['data']['network']
                else:
                        return None

	def is_user_utilized(self, ref_str):
		"""
		Return True if user is used somewhere in nodes or objects False otherwise 
		"""
		user_name = self.get_name_by_ref(ref_str)
		if user_name in default_users: return True

		if self.get_affected_nodes(ref_str): return True
		if [o for o in self.get_affected_objects(ref_str) if o not in (ref_str)] : return True
		
		user_network_ref = self.get_user_network_ref(ref_str)
		if [o for o in self.get_affected_objects(user_network_ref) if o not in (ref_str, user_network_ref)]:
			return True
		
		if self.get_affected_nodes(user_network_ref): return True	
		
		return False

	def is_object_used(self, ref_str):
		"""
		Return True if user is used somewhere in nodes or objects False otherwise 
		"""
		if self.get_affected_nodes(ref_str): return True
		if len(self.get_affected_objects(ref_str)) > 1 : return True
		
		return False



	def get_all_users(self):
		"""
		get_all_users - returns all users
		"""
		return self.users_list
	
	def delete_user(self, user_ref):
		"""
			Deletes user if it's unused, then delete user network object if it is unused
		"""
		logging.info(user_ref)
		if not user_ref:
			logging.info('None as user_ref, will not delete him')
                        return
		if not self.user_exists(user_ref): 
			logging.info('User %s does not exists, will not delete him', user_ref)
			return
		if self.is_user_utilized(user_ref): 
			logging.info('User %s is utilized, will not delete him', user_ref)
			return 
		network_ref = self.get_user_network_ref(user_ref)
		delete_user_command = r"echo -e 'OBJS\ndelete %s' | %s --batch" % (user_ref, cc)

		#print(delete_user_command)
		logging.info(delete_user_command)

		sp_output = subprocess.check_output(delete_user_command, shell=True)

		#print(sp_output)
		logging.info(sp_output)

		if not network_ref: return

		delete_network_command = r"echo -e 'OBJS\ndelete %s' | %s --batch" % (network_ref, cc)

		#print(delete_network_command)
		logging.info(delete_network_command)

		sp_output = subprocess.check_output(delete_network_command, shell=True)

		#print(sp_output)
		logging.info(sp_output)
	
	def examine_user(self, user_name):
		"""
		Prints out affected nodes, objects, is user used or not
		"""
		if not user_name:
			logging.info('None as username')
			return
		
		if not self.username_exists(user_name):
			logging.info('User %s does not exists', user_name)
			return
		affected_nodes = self.get_affected_nodes(self.get_ref_by_name(user_name))
		affected_objects = self.get_affected_objects(self.get_ref_by_name(user_name))
		
		is_used = self.is_user_utilized(self.get_ref_by_name(user_name))
		user_network = self.get_user_network_ref(self.get_ref_by_name(user_name))


		logging.info('---')
		logging.info('%s has affected nodes %s', user_name, str(affected_nodes))
		logging.info('%s has affected objects %s', user_name, str(affected_objects))
		logging.info('%s is used %s', user_name, str(is_used))
		if user_network:
			network_affected_nodes = self.get_affected_nodes(user_network)
			network_affected_objects = self.get_affected_objects(user_network)
			logging.info('%s has network %s', user_name, str(user_network))
			logging.info('Network %s has affected nodes %s', user_network, str(network_affected_nodes))
			logging.info('Network %s has affected objects %s', user_network, str(network_affected_objects))
		else:
			logging.info('%s has no network', user_name)
			
			
		


def import_user_dict(filename):
	"""
	import_user_dict returns list of imported objects from file filename

	"""
	with open(filename, 'r') as f:
		filetext = f.read()
	f.closed
	json_text = cc_output_to_json(filetext)
	return json.loads(json_text)	

def cc_output_to_json(cc_output):
	"""
	converts cc output to json
	"""
	converted_text = cc_output.replace(' => ', ': ').replace("'", '"')
	converted_text = re.sub(r'\\x{(\w+)}', resub_perl_hex_to_utf16, converted_text)
	return converted_text

def resub_perl_hex_to_utf16(matchobject):
	"""
	converts '\\x{430}' to '\\u0430'
	"""
	codepoint = matchobject.group(1)
	if len(codepoint) % 2 == 1: codepoint = '0' + codepoint
	return r'\u' + codepoint

def print_usage():
        
        text = "Usage: python " + sys.argv[0] + """ (--list_all|--list_unused|--examine|--delete) [user_list_file]

                This program is used for bulk user deletion in Sophos UTM. Sophos UTM lacks features of unused users provisioning and in the same time it is easy to flood system with hundreds or thousands users and corresponding network definitions. It is designed to be safe - it skips deletion of any users or networks that is used somewhere in UTM configuration. This script is intended to be run on Sophos UTM console with root priviledges.

                --list_all 
                    Lists all user objects.
                --list_unused
                    Lists all unused user objects. Unused means than user and corresponding network definition is not used in any UTM config sections(except List of existing users) and is not used in any other object definition.
                --examine
                    Reads list of users from file(one username per line) or from STDIN. Writes usage information for each user to Log file.
                --delete
                    Reads list of users from file(one username per line) or from STDIN. Deletes user and corresponding network object if they are unused in UTM, skips otherwise. Writes information to Log file.

                Log file suuc.log is located in the same directory.

                To remove all unused users with one command you can use: python suuc.py --list_unused | python suuc.py --delete

        """
	print(text)
	sys.exit()

def examine_users_file(file):
	"""
	reads usernames from file, one name per line. examines user and writes to log
	"""
	users = UTMUsers()
	users_counter = 0
	for line in file:
		username = line.rstrip()
		users.examine_user(username)
		users_counter += 1	
		sys.stdout.flush()
		sys.stdout.write('\r{0} users processed'.format(users_counter))
	print(", see {0} for details".format(logfile))

def delete_users_file(file):
	"""
	reads usernames from file and delete all of them if user is unused in system
	"""
	users = UTMUsers()
	users_counter = 0
	for line in file:
		username = line.rstrip()
		user_ref = users.get_ref_by_name(username)
		if user_ref: users.delete_user(user_ref)
		users_counter += 1	
		sys.stdout.flush()
		sys.stdout.write('\r{0} users processed'.format(users_counter))
	print(", see {0} for details".format(logfile))



def list_unused():
	"""
	Lists unused users one per line
	"""
	utm_users = UTMUsers()
	for u in utm_users.get_all_users():
		if not utm_users.is_user_utilized(u['ref']): print u['data']['name']
	return

def list_all():
	"""
	Lists all users one per line
	"""
	utm_users = UTMUsers()
	for u in utm_users.get_all_users(): print u['data']['name']
	return

def main():
	logging.info('Executed: %s', ' '.join(sys.argv))

	if len(sys.argv) == 3: file = open(sys.argv[2])
	elif len(sys.argv) == 2: file = sys.stdin
	else: 
		print_usage()

	
	if sys.argv[1] == '--examine': 
		examine_users_file(file)	
	elif sys.argv[1] == '--delete': 
		delete_users_file(file)	
	elif sys.argv[1] == '--list_unused': 
		list_unused()	
	elif sys.argv[1] == '--list_all': 
		list_all()	
	else:
		print_usage()
	
if __name__ == '__main__': main()





