def ip_to_bin(ip):
	octets = ip.split('.')
	octets_integer = [int(x) for x in octets]
	octets_bin = [bin(x)[2:] for x in octets_integer]
	output = ''
	for octet in octets_bin:
		if len(octet) < 8:
			left = 8 - len(octet)
			output += '0' * left
		output += octet
	return output

def bin_to_ip(binary):
	o1 = binary[0:8]
	o2 = binary[8:16]
	o3 = binary[16:24]
	o4 = binary[24:32]
	octets_bin = [o1,o2,o3,o4]
	output = '.'.join([str(int(x,2)) for x in octets_bin])
	return output

def int_to_bin(integer):
	binary = bin(integer)[2:]
	output = ''
	if len(binary) < 32:
		left = 32 - len(binary)
		output += '0' * left
	output += binary
	return output

def ip_range(start, end):
	'''
	returns a list of all IPs from start to end, inclusive
	'''
	s = ip_to_bin(start)
	f = ip_to_bin(end)
	output = []
	for middle in range(int(s,2),int(f,2)+1):
		binary = int_to_bin(middle)
		output.append(f'{bin_to_ip(binary)}/32')
	return output

def ip_range_single(input):
	start,end = input.split()
	s = ip_to_bin(start)
	f = ip_to_bin(end)
	output = []
	for middle in range(int(s,2),int(f,2)+1):
		binary = int_to_bin(middle)
		output.append(f'{bin_to_ip(binary)}/32')
	return output

def cidr_to_bin(cidr):
	output = '1' * cidr + '0' * (32-cidr)
	return output

def subnet_to_list(subnet):
	ip, cidr = subnet.split('/')
	cidr = int(cidr)
	cidr_mask = bin_to_ip(cidr_to_bin(cidr))
	network_bin = int_to_bin(int(ip_to_bin(cidr_mask),2) & int(ip_to_bin(ip),2))
	network = bin_to_ip(network_bin)
	broadcast_prepare = '0' * cidr + '1' * (32 - cidr)
	broadcast_bin = int_to_bin(int(ip_to_bin(network),2) ^ int(broadcast_prepare,2))
	broadcast = bin_to_ip(broadcast_bin)
	output = ip_range(network, broadcast)
	return output

def ip_and_mask_to_cidr(input):
	ip, mask = input.split()
	mask_bin = ip_to_bin(mask)
	mask_ones = mask_bin.count('1')
	output = f'{ip}/{mask_ones}'
	return output

def subnet_in_supernet(sub, sup):
	# subnet
	sub_ip, sub_cidr = sub.split('/')
	sub_cidr_int = int(sub_cidr)
	sub_ip_b, sub_cidr_b = ip_to_bin(sub_ip), cidr_to_bin(sub_cidr_int)
	sub_net = int(sub_ip_b,2) & int(sub_cidr_b,2)
	sub_net_b = int_to_bin(sub_net)
	# supernet
	sup_ip, sup_cidr = sup.split('/')
	sup_cidr_int = int(sup_cidr)
	sup_ip_b, sup_cidr_b = ip_to_bin(sup_ip), cidr_to_bin(sup_cidr_int)
	sup_net = int(sup_ip_b,2) & int(sup_cidr_b,2)
	sup_net_b = int_to_bin(sup_net)
	#
	if sub_net_b[:sup_cidr_int] == sup_net_b[:sup_cidr_int]:
		return True
	return False