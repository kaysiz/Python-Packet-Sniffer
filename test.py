import socket, struct
import threading,logging
from socket import inet_ntoa
from utils.enums import template_field
from utils.parse import parse

LOG_FILENAME = 'log.out'
#logging.basicConfig(filename=LOG_FILENAME,format='%(levelname)s:%(message)s',level=logging.DEBUG,)
logging.basicConfig(format='%(levelname)s:%(message)s',level=logging.DEBUG,)

SIZE_OF_HEADER = 20

#templates = [{"id":265,"data_length":48,"description":[{"field_type": 21, "field_length": 4}, {"field_type": 22, "field_length": 4}, {"field_type": 1, "field_length": 4}, {"field_type": 2, "field_length": 4}, {"field_type": 10, "field_length": 2}, {"field_type": 14, "field_length": 2}, {"field_type": 8, "field_length": 4}, {"field_type": 12, "field_length": 4}, {"field_type": 4, "field_length": 1}, {"field_type": 5, "field_length": 1}, {"field_type": 7, "field_length": 2}, {"field_type": 11, "field_length": 2}, {"field_type": 48, "field_length": 1}, {"field_type": 51, "field_length":1}, {"field_type": 15, "field_length": 4}, {"field_type": 13, "field_length": 1}, {"field_type": 9, "field_length": 1}, {"field_type": 6, "field_length": 1}, {"field_type": 61, "field_length": 1}, {"field_type": 17, "field_length": 2}, {"field_type": 16, "field_length": 2}]}]

templates=[]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 2055))

def processPacket(data,addr):
    (version, count) = struct.unpack('!HH',data[0:4])
    logging.debug("Version %s, count %s "%(version,count))
    if version != 9:
       logging.error("Not NetFlow v9!")
       return None
    uptime = socket.ntohl(struct.unpack('I',data[4:8])[0])
    epochseconds = socket.ntohl(struct.unpack('I',data[8:12])[0])
    logging.debug("Uptime %s , epochseconds %s "% (uptime, epochseconds))
    data=data[SIZE_OF_HEADER:]
    while len(data) >0:
        (flow_set_id, flow_set_length) = struct.unpack('!HH',data[0:4])
        logging.debug("flow_set_id %d, flow_set_length %d "%(flow_set_id,flow_set_length))
        my_data = data[4:flow_set_length]
        data = data[flow_set_length:]
        if flow_set_id == 0:
           # data template found.
           template={}
           (template_id, template_field_length) = struct.unpack('!HH',my_data[0:4])
           logging.debug("template_id %d, template_field_length %d "%(template_id,template_field_length))
           my_data=my_data[4:]
           template['id']= template_id
           template['description']=[]
           template['data_length']=0
           template['address']=addr[0]
           for i in xrange(0,template_field_length*4,4):
               template_element={}
               template_element['field_type']=parse(my_data[i:i+2],"INT",2)
               template_field_length = parse(my_data[i+2:i+4],"INT",2)
               template_element['field_length']=template_field_length
               template['data_length'] += template_field_length
               template['description'].append(template_element)
           for temp in templates:
               if temp["id"]== template_id:
                  #update dict
                  templates.remove(temp)
                  break
           templates.append(template)
           logging.debug(templates)


        if flow_set_id == 1:  # options template found.Lets add it to template list
            while len(my_data) >6:
              template={}
              (template_id, option_scope_length) = struct.unpack('!HH',my_data[0:4])
              logging.debug("option template_id %d, option_scope_length %d "%(template_id,option_scope_length))
              option_length = struct.unpack('!H',my_data[4:6])[0]
              my_data=my_data[6:]
              if template_id == 0 or option_scope_length >0:
                 # probably padding or special case. Right now not handling
                 my_data=my_data[option_scope_length:]
                 break
              else:
                 template['id']= template_id
                 template['description']=[]
                 template['data_length']=0
                 template['address']=addr[0]
                 for i in xrange(0,option_length,4):
                     template_element={}
                     template_element['field_type']=parse(my_data[i:i+2],"INT",2)
                     template_field_length = parse(my_data[i+2:i+4],"INT",2)
                     template_element['field_length']=template_field_length
                     template['data_length'] += template_field_length
                     template['description'].append(template_element)
                 for temp in templates:
                     if temp["id"]== template_id:
                        #update dict
                        templates.remove(temp)
                        break
                 templates.append(template)
                 logging.debug(templates)
              my_data=my_data[option_length:]
              #padding = flow_set_length - (10 +option_scope_length + option_length)
              #my_data=my_data[padding:]
        if flow_set_id > 255:
        # let us parse flow data
        # first check if template present
            my_template = None
            for template in templates:
                if flow_set_id == template["id"] and addr[0] == template['address']: #check if template from same ip exist
                    my_template = template
                    break
            if not my_template:
                logging.debug("No suitable template found")
            else:
                nf_data=[]
                template_total_data_length = my_template['data_length']
                while len(my_data) >= template_total_data_length:
                    for field in my_template['description']:
                        field_name = template_field[field['field_type']]['name']
                        field_type = template_field[field['field_type']]['data_type']
                        field_length = field['field_length']
                        if field_length ==0:
                            field_length = template_field[field['field_type']]['default']
                        logging.debug("Data length = %d "%(field_length))
                        ext_data = parse(my_data[:field_length],field_type,field_length)
                        logging.debug ("%s : %s"%(field_name, ext_data))
                        nf_data.append({field_name:ext_data})
                        my_data = my_data[field_length:]
                logging.info(nf_data)


while True:
    buf, addr = sock.recvfrom(1500)
    t = threading.Thread(target=processPacket, args=(buf,addr))
    t.start()