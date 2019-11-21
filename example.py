import socket
import sys
import binascii
from struct import unpack, calcsize
from netflow.v9 import V9ExportPacket, TemplateNotRecognized

class Flow(object):
	# Virtual base class
	LENGTH = 0
	def __init__(self, data):
		if len(data) != self.LENGTH:
			raise ValueError("Short flow")

	def _int_to_ipv4(self, addr):
		return "%d.%d.%d.%d" % \
		   (addr >> 24 & 0xff, addr >> 16 & 0xff, \
		    addr >> 8 & 0xff, addr & 0xff)

class Header(object):
	# Virtual base class
	LENGTH = 0
	def __init__(self, data):
		if len(data) != self.LENGTH:
			raise ValueError("Short flow header")

class Header1(Header):
	LENGTH = calcsize("!HHIII")
	def __init__(self, data):
		if len(data) != self.LENGTH:
			raise ValueError("Short flow header")
			
		_nh = unpack("!HHIII", data)
		self.version = _nh[0]
		self.num_flows = _nh[1]
		self.sys_uptime = _nh[2]
		self.time_secs = _nh[3]
		self.time_nsecs = _nh[4]

	def __str__(self):
		ret  = "NetFlow Header v.%d containing %d flows\n" % \
		    (self.version, self.num_flows)
		ret += "    Router uptime: %d\n" % self.sys_uptime
		ret += "    Current time:  %d.%09d\n" % \
		    (self.time_secs, self.time_nsecs)

		return ret

class Flow1(Flow):
	LENGTH = calcsize("!IIIHHIIIIHHHBBBBBBI")
	def __init__(self, data):
		if len(data) != self.LENGTH:
			raise ValueError("Short flow")
			
		_ff = unpack("!IIIHHIIIIHHHBBBBBBI", data)
		self.src_addr = self._int_to_ipv4(_ff[0])
		self.dst_addr = self._int_to_ipv4(_ff[1])
		self.next_hop = self._int_to_ipv4(_ff[2])
		self.in_index = _ff[3]
		self.out_index = _ff[4]
		self.packets = _ff[5]
		self.octets = _ff[6]
		self.start = _ff[7]
		self.finish = _ff[8]
		self.src_port = _ff[9]
		self.dst_port = _ff[10]
		# pad
		self.protocol = _ff[12]
		self.tos = _ff[13]
		self.tcp_flags = _ff[14]

	def __str__(self):
		ret = "proto %d %s:%d > %s:%d %d bytes" % \
		    (self.protocol, self.src_addr, self.src_port, \
		     self.dst_addr, self.dst_port, self.octets)
		return ret

class NetFlowPacket:
	FLOW_TYPES = {
		1 : (Header1, Flow1),
	}
	def __init__(self, data):
		if len(data) < 16:
			raise ValueError("Short packet")
		_nf = unpack("!H", data[:2])
		self.version = _nf[0]

		if not self.version in self.FLOW_TYPES.keys():
			raise RuntimeWarning("NetFlow version %d is not yet implemented" % self.version)
		hdr_class = self.FLOW_TYPES[self.version][0]
		flow_class = self.FLOW_TYPES[self.version][1]

		self.hdr = hdr_class(data[:hdr_class.LENGTH])

		if len(data) - self.hdr.LENGTH != \
		   (self.hdr.num_flows * flow_class.LENGTH):
			raise ValueError("Packet truncated in flow data")
		
		self.flows = []
		for n in range(self.hdr.num_flows):
			offset = self.hdr.LENGTH + (flow_class.LENGTH * n)
			flow_data = data[offset:offset + flow_class.LENGTH]
			self.flows.append(flow_class(flow_data))

	def __str__(self):
		ret = str(self.hdr)
		i = 0
		for flow in self.flows:
			ret += "Flow %d: " % i
			ret += "%s\n" % str(flow)
			i += 1

		return ret

def store_template_flowset(data):
    
    offset = 20
    
    template_flowset_header = unpack('!HHHH', data[offset:offset+8])
    template_flowset_id = template_flowset_header[0]
    template_flowset_length = template_flowset_header[1]
    template_flowset_template_id = template_flowset_header[2]
    template_flowset_field_count = template_flowset_header[3]
    template_fields_type_length = {}
    # iterate through all the template records in this template flowset
    offset = offset + 8
    i = 0
    for template_redord in range(template_flowset_field_count):
        # get all the fields in this template flowset
        template_field_type, template_field_length = unpack('!HH', data[offset:offset+4])
        # create a dictionary for 
        template_fields_type_length[(template_flowset_template_id, template_redord)] = (template_field_type, template_field_length)
        offset += 4
        i += 1
    return template_fields_type_length, template_flowset_length, template_flowset_field_count, offset

host = ''
port = 2055

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.bind((host, port))
except socket.error as e:
    print(str(e))

s.listen(5)
while True:
    
    # conn, addr = s.accept()
    # templates = {}
    # packet, data = conn.recvfrom(65565)
    # print(store_template_flowset(packet))
    
    # if unpack("!H", packet[:2])[0] == 9:
    #     print(V9ExportPacket(packet, templates))
    data = s.recv(1518)
	nfHeader = struct.unpack('!HHLLLL', data[0:20])
	for flow in range(0, nfHeader[1]):
		if flow == 0:
			firstFlow = struct.unpack('!IIIIIIIIBBHHBIBBBHH', data[24:74])
			print(firstFlow)
		else:
			offset = flow * templSize
			subseqFlow = struct.unpack('!IIIIIIIIBBHHBIBBBHH', data[24 + offset:74 + offset])
			print(subseqFlow)
    # print("blows up")
    # print(packet)
    # print(packet[:2][0])
    #packet string from tuple
    # packet = packet[0]

    # # take the first 20 characters of the ip header
    # ip_header = packet[0:20]

    # # now upack them
    # iph = unpack('!BBHHHBBH4s4s', ip_header)
    # # print(unpack('!H', ip_header))

    # version_ihl = iph[0]
    # version = version_ihl >> 4
    # ihl = version_ihl &  0xF

    # iph_length = ihl * 4

    # ttl = iph[5]
    # protocol = iph[6]
    # s_addr = socket.inet_ntoa(iph[8]);
    # d_addr = socket.inet_ntoa(iph[9]);

    # print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

    # tcp_header = packet[iph_length:iph_length+20]

    # #now unpack them :)
    # tcph = unpack('!HHLLBBHHH' , tcp_header)

    # source_port = tcph[0]
    # dest_port = tcph[1]
    # sequence = tcph[2]
    # acknowledgement = tcph[3]
    # doff_reserved = tcph[4]
    # tcph_length = doff_reserved >> 4
    # # print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
    # # print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))

    # h_size = iph_length + tcph_length * 4
    # data_size = len(packet) - h_size

    # #get data from the packet
    # data = packet[h_size:]

    # #sys.stdout.buffer.write(data)
    # # print('Data : ' + str(data))