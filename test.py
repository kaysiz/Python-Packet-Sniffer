import socket
import struct
import sys


HOST = "127.0.0.1"
PORT = 2055


field_types = {
    1: 'IN_BYTES',
    2: 'IN_PKTS',
    3: 'FLOWS',
    4: 'PROTOCOL',
    5: 'SRC_TOS',
    6: 'TCP_FLAGS',
    7: 'L4_SRC_PORT',
    8: 'IPV4_SRC_ADDR',
    9: 'SRC_MASK',
    10: 'INPUT_SNMP',
    11: 'L4_DST_PORT',
    12: 'IPV4_DST_ADDR',
    13: 'DST_MASK',
    14: 'OUTPUT_SNMP',
    15: 'IPV4_NEXT_HOP',
    16: 'SRC_AS',
    17: 'DST_AS',
    18: 'BGP_IPV4_NEXT_HOP',
    19: 'MUL_DST_PKTS',
    20: 'MUL_DST_BYTES',
    21: 'LAST_SWITCHED',
    22: 'FIRST_SWITCHED',
    23: 'OUT_BYTES',
    24: 'OUT_PKTS',
    25: 'MIN_PKT_LNGTH',
    26: 'MAX_PKT_LNGTH',
    27: 'IPV6_SRC_ADDR',
    28: 'IPV6_DST_ADDR',
    29: 'IPV6_SRC_MASK',
    30: 'IPV6_DST_MASK',
    31: 'IPV6_FLOW_LABEL',
    32: 'ICMP_TYPE',
    33: 'MUL_IGMP_TYPE',
    34: 'SAMPLING_INTERVAL',
    35: 'SAMPLING_ALGORITHM',
    36: 'FLOW_ACTIVE_TIMEOUT',
    37: 'FLOW_INACTIVE_TIMEOUT',
    38: 'ENGINE_TYPE',
    39: 'ENGINE_ID',
    40: 'TOTAL_BYTES_EXP',
    41: 'TOTAL_PKTS_EXP',
    42: 'TOTAL_FLOWS_EXP',
    # 43 vendor proprietary
    44: 'IPV4_SRC_PREFIX',
    45: 'IPV4_DST_PREFIX',
    46: 'MPLS_TOP_LABEL_TYPE',
    47: 'MPLS_TOP_LABEL_IP_ADDR',
    48: 'FLOW_SAMPLER_ID',
    49: 'FLOW_SAMPLER_MODE',
    50: 'NTERVAL',
    # 51 vendor proprietary
    52: 'MIN_TTL',
    53: 'MAX_TTL',
    54: 'IPV4_IDENT',
    55: 'DST_TOS',
    56: 'IN_SRC_MAC',
    57: 'OUT_DST_MAC',
    58: 'SRC_VLAN',
    59: 'DST_VLAN',
    60: 'IP_PROTOCOL_VERSION',
    61: 'DIRECTION',
    62: 'IPV6_NEXT_HOP',
    63: 'BPG_IPV6_NEXT_HOP',
    64: 'IPV6_OPTION_HEADERS',
    # 65-69 vendor proprietary
    70: 'MPLS_LABEL_1',
    71: 'MPLS_LABEL_2',
    72: 'MPLS_LABEL_3',
    73: 'MPLS_LABEL_4',
    74: 'MPLS_LABEL_5',
    75: 'MPLS_LABEL_6',
    76: 'MPLS_LABEL_7',
    77: 'MPLS_LABEL_8',
    78: 'MPLS_LABEL_9',
    79: 'MPLS_LABEL_10',
    80: 'IN_DST_MAC',
    81: 'OUT_SRC_MAC',
    82: 'IF_NAME',
    83: 'IF_DESC',
    84: 'SAMPLER_NAME',
    85: 'IN_PERMANENT_BYTES',
    86: 'IN_PERMANENT_PKTS',
    # 87 vendor property
    88: 'FRAGMENT_OFFSET',
    89: 'FORWARDING STATUS',
}


def read_header(data):
    pack = struct.unpack('!HHIIII', data[:20])
    
    header_version = pack[0]
    header_count = pack[1]  # number of FlowSet records (both template and data) within this packet. not sure if correct. softflowd: no of flows
    header_uptime = pack[2]
    header_timestamp = pack[3]
    header_sequence = pack[4]
    header_source_id = pack[5]
    return


def get_flowset_id(data):
    flowset_id = struct.unpack('!H', data[20:22])[0] # read the FlowSet ID which is 2 bytes; bytes 20 to 22
    print("flowset_id = %s" % flowset_id)
    return flowset_id


def store_template_flowset(data):
    template_flowset_header = struct.unpack('!HHHH', data[offset:offset+8])
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
        template_field_type, template_field_length = struct.unpack('!HH', data[offset:offset+4])
        # create a dictionary for 
        template_fields_type_length[(template_flowset_template_id, template_redord)] = (template_field_type, template_field_length)
        offset += 4
        i += 1
    return template_fields_type_length, template_flowset_length, template_flowset_field_count, offset


def read_data_flowset(data):
    data_flowset_header = struct.unpack('!HH', data[offset:offset+4])   
    data_flowset_id = data_flowset_header[0]
    data_flowset_length = data_flowset_header[1]
    
    data_flowset_padding_size = 4 - (data_flowset_length % 4)
    
    flows = []
    offset = 4
    i = 0
    
    data_flowset_records = struct.unpack('!%dH' %(data_flowset_length/2), data[offset:])
    
    while offset <= (data_flowset_length - data_flowset_padding_size):
        for data_record in range(template_flowset_field_count):
            data_record_type = template_fields_type_length[(data_flowset_id, data_record)][0]
            data_record_length = template_fields_type_length[(data_flowset_id, data_record)][1]
            
            flows.append((data_record_type, data_flowset_records[data_record]))
            offset += data_record_length    


def get_length_field(data):

    if flowset_id == 0:  # TemplateFlowSet always has an id = 0
        template_flowset = TemplateFlowSet(data[20:])
                self.templates.update(tfs.templates)
                offset += tfs.length
    else:
        data_flowset = ""


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))
print("Listening on interface {}:{}".format(HOST, PORT))

while True:
    (data, sender) = sock.recvfrom(8192)
    print("Received data from {}, length {}".format(sender, len(data)))