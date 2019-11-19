import socket
import sys
import binascii
from struct import unpack, calcsize


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
        9 : (Header9, Flow9),
	}
	def __init__(self, data):
		if len(data) < 16:
			raise ValueError("Short packet")
		_nf = unpack("!H", data[:2])
		self.version = _nf[0]

		if not self.version in self.FLOW_TYPES.keys():
			raise RuntimeWarning("NetFlow version %d is not yet implemented" % self.version)
        template = {}
        try:
            export = parse_packet(data, templates)
        except UnknownNetFlowVersion as e:
            logger.error("%s, ignoring the packet", e)
            continue
        except TemplateNotRecognized:
            logger.debug("Failed to decode a v9 ExportPacket - will "
                            "re-attempt when a new template is discovered")
            continue

        logger.debug("Processed a v%d ExportPacket with %d flows.",
                             export.header.version, export.header.count)
	# 	hdr_class = self.FLOW_TYPES[self.version][0]
	# 	flow_class = self.FLOW_TYPES[self.version][1]

	# 	self.hdr = hdr_class(data[:hdr_class.LENGTH])

	# 	if len(data) - self.hdr.LENGTH != \
	# 	   (self.hdr.num_flows * flow_class.LENGTH):
	# 		raise ValueError("Packet truncated in flow data")
		
	# 	self.flows = []
	# 	for n in range(self.hdr.num_flows):
	# 		offset = self.hdr.LENGTH + (flow_class.LENGTH * n)
	# 		flow_data = data[offset:offset + flow_class.LENGTH]
	# 		self.flows.append(flow_class(flow_data))

	# def __str__(self):
	# 	ret = str(self.hdr)
	# 	i = 0
	# 	for flow in self.flows:
	# 		ret += "Flow %d: " % i
	# 		ret += "%s\n" % str(flow)
	# 		i += 1

	# 	return ret




# def run(self):
#         # Process packets from the queue
#         try:
#             templates = {}
#             to_retry = []
#             while not self._shutdown.is_set():

#                 try:
#                     export = parse_packet(pkt.data, templates)
#                 except UnknownNetFlowVersion as e:
#                     logger.error("%s, ignoring the packet", e)
#                     continue
#                 except TemplateNotRecognized:
#                     if time.time() - pkt.ts > PACKET_TIMEOUT:
#                         logger.warning("Dropping an old and undecodable v9 ExportPacket")
#                     else:
#                         to_retry.append(pkt)
#                         logger.debug("Failed to decode a v9 ExportPacket - will "
#                                      "re-attempt when a new template is discovered")
#                     continue

#                 logger.debug("Processed a v%d ExportPacket with %d flows.",
#                              export.header.version, export.header.count)

#                 # If any new templates were discovered, dump the unprocessable
#                 # data back into the queue and try to decode them again
#                 if export.header.version == 9 and export.contains_new_templates and to_retry:
#                     logger.debug("Received new template(s)")
#                     logger.debug("Will re-attempt to decode %d old v9 ExportPackets",
#                                  len(to_retry))
#                     for p in to_retry:
#                         self.input.put(p)
#                     to_retry.clear()

#                 self.output.put((pkt.ts, pkt.client, export))
#         finally:
#             self.server.shutdown()
#             self.server.server_close()




host = ''
port = 2055

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.bind((host, port))
except socket.error as e:
    print(str(e))

s.listen(5)
while True:
    
    conn, addr = s.accept()
    packet, data = conn.recvfrom(65565)
    NetFlowPacket(packet)
    # print(packet)
    # print(packet[:2][0])
    #packet string from tuple
    packet = packet[0]

    # take the first 20 characters of the ip header
    ip_header = packet[0:20]

    # now upack them
    iph = unpack('!BBHHHBBH4s4s', ip_header)
    # print(unpack('!H', ip_header))

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl &  0xF

    iph_length = ihl * 4

    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);

    print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

    tcp_header = packet[iph_length:iph_length+20]

    #now unpack them :)
    tcph = unpack('!HHLLBBHHH' , tcp_header)

    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    # print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
    # print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))

    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size

    #get data from the packet
    data = packet[h_size:]

    #sys.stdout.buffer.write(data)
    # print('Data : ' + str(data))