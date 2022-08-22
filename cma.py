import json
import requests
requests.packages.urllib3.disable_warnings()

import class_tools as tools
from timestamp.timestamp import timestamp

class Checkpoint(object):
	def __init__(self, config=None, domain=''):
		self.config = config
		self.domain = domain
		self.object_ref = {}
		self.session = requests.Session()
		self.session.trust_env = False
		headers = {
			'Content-Type': 'application/json',
		}
		self.session.headers = headers
		if config is None:
			print('[E] No configuration filename not provided')
		else:
			self.login(domain=domain)
		return
	
	def load_configuration(self, config):
		import os
		config_file = 'configuration.json'
		__file__ = 'cma.py'
		path = os.path.abspath(__file__)
		dir_path = os.path.dirname(path)
		with open(f'{dir_path}/{config_file}','r') as f:
			raw_file = f.read()
		config_raw = json.loads(raw_file)
		if config not in config_raw['servers']:
			print(f'[E] Configuration not found in configuration.json ({self.config})')
			output = {
				'host': '',
				'username': '',
				'password': '',
			}
			return output
		else:
			connection_info = config_raw['servers'][config]
			self.host = connection_info['host']
			self.base_url = f'https://{self.host}/web_api'
			output = {
				'host': self.host,
				'username': connection_info['username'],
				'password': connection_info['password'],
			}
			return output
		return
	
	def post(self, path, data={}):
		url = f'{self.base_url}{path}'
		response_raw = self.session.post(
			url,
			json=data,
			verify=False
		)
		output = {
			'success': False,
			'result': '',
			'response': response_raw,
		}
		if response_raw.status_code == 200:
			response_json = json.loads(response_raw.text)
			output['result'] = response_json
			output['success'] = True
		else:
			# login again
			pass
		return output
	
	def login(self, domain=''):
		path = '/login'
		if 'X-chkp-sid' in self.session.headers:
			self.logout()
		connection_info = self.load_configuration(self.config)
		authentication_params = {
			'user': connection_info['username'],
			'password': connection_info['password'],
			'domain': domain,
		}
		self.domain = domain
		output = self.post(path, data=authentication_params)
		token = ''
		if output['success']:
			token = output['result']['sid']
			self.token = token
			header = {
				'X-chkp-sid': token,
			}
			self.session.headers.update(header)
			print(f'[I] Login ({self.config} - {self.domain}) ... OK ({self.token})')
		else:
			print(f'[I] Login ({self.config} - {self.domain}) ... FAIL')
		return
	
	def logout(self):
		path = '/logout'
		output = self.post(path)
		if output['success']:
			self.session.headers = {'Content-Type': 'application/json'}
			print(f'[I] Logout ({self.config} - {self.domain}) ... {output["result"]["message"]} ({self.token})')
		else:
			print(f'[I] Logout ({self.config} - {self.domain}) ... FAIL')
		return
	
	def get_command(self, command, params={}):
		path = f'/{command}'
		output = self.post(path, data=params)
		if 'total' in output['result']:
			total = output['result']['total']
			print(f'[I] Found {total} items for "{command}"')
		else:
			pass
		return output
	
	def get_domain_list(self):
		command = 'show-domains'
		output = self.get_command(command)
		return output
	
	def get_domain_by_name(self, name):
		command = 'show-domain'
		params = {
			'name': name,
			'details-level': 'full',
		}
		output = self.get_command(command, params=params)
		return output
	
	def get_domain_by_uid(self, uid):
		command = 'show-domain'
		params = {
			'uid': uid,
			'details-level': 'full',
		}
		output = self.get_command(command, params=params)
		return output
	
	def get_object_by_name(self, name):
		command = 'show-object'
		params = {
			'name': name,
			'details-level': 'full',
		}
		output = self.get_command(command, params=params)
		return output
	
	def get_object_by_uid(self, uid):
		command = 'show-object'
		params = {
			'uid': uid,
			'details-level': 'full',
		}
		output = self.get_command(command, params=params)
		return output
	
	def get_domain_servers_by_name(self, name):
		domain = self.get_domain_by_name(name)
		output = domain['result']['servers']
		return output
	
	def get_domain_servers_by_uid(self, uid):
		domain = self.get_domain_by_uid(uid)
		output = domain['result']['servers']
		return output
	
	def get_package_list(self, offset=0):
		command = 'show-packages'
		params = {
			'details-level': 'full',
			'limit': 500,
			'offset': offset,
		}
		output = self.get_command(command, params=params)
		return output
	
	def get_object_list(self, offset=0):
		command = 'show-objects'
		params = {
			'details-level': 'full',
			'limit': 500,
			'offset': offset,
		}
		output = self.get_command(command, params=params)
		return output
	
	def get_access_rule_list(self, layer, offset=0):
		command = 'show-access-rulebase'
		params = {
			'uid': layer,
			'details-level': 'full',
			'use-object-dictionary': True,
			'limit': 500,
			'offset': offset,
		}
		output = self.get_command(command, params=params)
		return output
	
	def get_access_layer_list(self, offset=0):
		command = 'show-access-layers'
		params = {
			'details-level': 'full',
			'limit': 500,
			'offset': offset,
		}
		output = self.get_command(command, params=params)
		return output
	
	def get_nat_rule_list(self, package, offset=0):
		command = 'show-nat-rulebase'
		params = {
			'package': package,
			'details-level': 'full',
			'limit': 500,
			'offset': offset,
		}
		output = self.get_command(command, params=params)
		return output
	
	def flatten_object(self, obj):
		if obj['uid'] in self.object_ref: return
		if obj['type'] == 'RulebaseAction':
			self.object_ref[obj['uid']] = obj['name']
		elif obj['type'] == 'group':
			self.object_ref[obj['uid']] = []
			for member in obj['members']:
				if type(member) is not dict:
					if member in obj['uid']: continue
					obj_sub = self.get_object_by_uid(member)
					self.flatten_object(obj_sub['result']['object'])
					if obj_sub['result']['object']['type'] == 'group':
						for member in obj_sub['result']['object']['members']:
							if member['uid'] not in self.object_ref:
								self.flatten_object(member)
							member_value = self.object_ref[
								member['uid']
							]
							self.object_ref[obj['uid']].extend(
								member_value
							)
					else:
						member_value = self.object_ref[
							obj_sub['result']['object']['uid']
						]
						self.object_ref[obj['uid']].extend(
							member_value
						)
				else:
					if member['uid'] not in self.object_ref:
						self.flatten_object(member)
					member_value = self.object_ref[
						member['uid']
					]
					self.object_ref[obj['uid']].extend(
						member_value
					)
		elif obj['type'] == 'CpmiAnyObject':
			self.object_ref[obj['uid']] = [obj['name']]
		elif obj['type'] == 'CpmiClusterMember':
			self.object_ref[obj['uid']] = [f'{obj["ipv4-address"]}/32']
		elif obj['type'] == 'CpmiGatewayCluster':
			self.object_ref[obj['uid']] = [f'{obj["ipv4-address"]}/32']
		elif obj['type'] == 'service-group':
			self.object_ref[obj['uid']] = []
			for member in obj['members']:
				# uid
				if type(member) is not dict:
					if member in obj['uid']: continue
					obj_sub = self.get_object_by_uid(member)
					self.flatten_object(obj_sub['result']['object'])
					# type service-group
					if obj_sub['result']['object']['type'] == 'service-group':
						for member in obj_sub['result']['object']['members']:
							if member['uid'] not in self.object_ref:
								self.flatten_object(member)
							member_value = self.object_ref[
								member['uid']
							]
							self.object_ref[obj['uid']].extend(
								member_value
							)
					# type other
					else:
						if obj_sub['result']['object']['uid'] not in self.object_ref:
							self.flatten_object(obj_sub['result']['object'])
						member_value = self.object_ref[
							obj_sub['result']['object']['uid']
						]
						self.object_ref[obj['uid']].extend(
							member_value
						)
				# object
				else:
					if member['uid'] not in self.object_ref:
						self.flatten_object(member)
					member_value = self.object_ref[
						member['uid']
					]
					self.object_ref[obj['uid']].extend(
						member_value
					)
		elif obj['type'] == 'host':
			self.object_ref[obj['uid']] = [f'{obj["ipv4-address"]}/32']
		elif obj['type'] == 'service-other':
			self.object_ref[obj['uid']] = []
			if 'groups' in obj:
				# usually only 1 group holding members
				for member in obj['groups'][0]['members']:
					# member is uid
					if member in self.object_ref: continue
					obj_sub = self.get_object_by_uid(member)
					self.flatten_object(obj_sub['result']['object'])
					member_value = self.object_ref[
						member
					]
					self.object_ref[obj['uid']].extend(
						member_value
					)
			# match might be port
			elif 'match' in obj:
				self.object_ref[obj['uid']] = [f'{obj["ip-protocol"]}/{obj["match"]}']
			# not sure where port is
			else:
				self.object_ref[obj['uid']] = [f'{obj["ip-protocol"]}/?']
		elif obj['type'] == 'service-icmp':
			if type(obj['icmp-type']) is int:
				self.object_ref[obj['uid']] = [f'icmp/{obj["icmp-type"]}']
			elif '-' in obj['icmp-type']:
				self.object_ref[obj['uid']] = self.get_service_expanded(
					'icmp',
					obj['icmp-type'],
				)
			else:
				self.object_ref[obj['uid']] = [f'icmp/{obj["icmp-type"]}']
		elif obj['type'] == 'network':
			self.object_ref[obj['uid']] = [f'{obj["subnet4"]}/{obj["mask-length4"]}']
		elif obj['type'] == 'service-tcp':
			if type(obj['port']) is int:
				self.object_ref[obj['uid']] = [f'tcp/{obj["port"]}']
			elif '-' in obj['port']:
				self.object_ref[obj['uid']] = self.get_service_expanded(
					'tcp',
					obj['port'],
				)
			else:
				self.object_ref[obj['uid']] = [f'tcp/{obj["port"]}']
		elif obj['type'] == 'Track':
			self.object_ref[obj['uid']] = obj['name']
		elif obj['type'] == 'Global':
			self.object_ref[obj['uid']] = obj['name']
		elif obj['type'] == 'service-udp':
			if type(obj['port']) is int:
				self.object_ref[obj['uid']] = [f'udp/{obj["port"]}']
			elif '-' in obj['port']:
				self.object_ref[obj['uid']] = self.get_service_expanded(
					'udp',
					obj['port'],
				)
			else:
				self.object_ref[obj['uid']] = [f'udp/{obj["port"]}']
		elif obj['type'] == 'address-range':
			self.object_ref[obj['uid']] = tools.ip_range(
				obj['ipv4-address-first'],
				obj['ipv4-address-last'],
			)
		else:
			print('else',obj)
		return
	
	def get_service_expanded(self, protocol, ports):
		output = []
		a, z = ports.split('-')
		for x in range(int(a), int(z)+1):
			#print(f'{protocol}/{x}')
			output.append(
				f'{protocol}/{x}'
			)
		return output
	
	def _(self):
		return

if __name__ == '__main__':
	__file__ = 'cma.py'
	host = 'lab'
	c = Checkpoint(config=host, domain='Domain01')
	#c.login(domain='Domain01')
	
	def print_rule(rule):
		global c
		src = []
		dst = []
		svc = []
		for x in rule_sub['source']:
			src.extend(c.object_ref[x])
		for x in rule_sub['destination']:
			dst.extend(c.object_ref[x])
		for x in rule_sub['service']:
			svc.extend(c.object_ref[x])
		for s in src:
			for d in dst:
				for v in svc:
					print('\t_', c.object_ref[rule_sub['action']], s, '--', d, '--', v)
		return
	
	otypes = []
	al = c.get_access_layer_list()
	#aln = al['result']['access-layers'][0]['name']
	for access in al['result']['access-layers']:
		aln = access['uid']
		ar = c.get_access_rule_list(aln)
		if not ar['success']:
			print(ar['response'].text)
			continue
		
		# objects-dictionary
		for _obj in ar['result']['objects-dictionary']:
			if _obj['type'] not in otypes: otypes.append(_obj['type'])
			if _obj['uid'] not in c.object_ref:	c.flatten_object(_obj)
		#
		#'''
		for rule in ar['result']['rulebase']:
			if rule['type'] == 'access-section':
				print(rule['name'])
				for rule_sub in rule['rulebase']:
					print_rule(rule_sub)
			elif rule['type'] == 'place-holder':
				pass
			else:
				if 'source' not in rule:
					print(rule)
				else:
					print_rule(rule)
		#'''
	
	c.logout()
	print('[I] End')