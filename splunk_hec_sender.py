#!/usr/local/bin/python3

# Send data to Splunk HEC

import os
import datetime
import time
import socket
import json
from configparser import ConfigParser
import requests
import datetime

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


cfg = ConfigParser()
cfg.read('noisemaker.conf')

hec_endpoint = cfg.get('splunk_hec', 'hec_endpoint')
token = cfg.get('splunk_hec', 'token')
hec_index = 'hec'

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    return(local_ip)

def create_json_data(event_list,source):
    # This function takes a list key-value pairs as event data and makes a json object
    # to send to Splunk HEC
    epoch = time.strftime("%s", time.localtime())
    index = hec_index
    host = os.uname()[1]
    sourcetype = "noisemaker::log"
    # create dictionary that will hold key-value pairs for Splunk event
    event_dict = {"time": epoch, "host": host, "sourcetype": sourcetype, "source": source, "index": index}
    event_dict["event"] = ' '.join(event_list)
    json_event = json.dumps(event_dict)
    send_to_splunk_hec(json_event)

def send_to_splunk_hec(json_event):
    # this does what it says
    authHeader = {'Authorization': token}
    r = requests.post(hec_endpoint, headers=authHeader, data=json_event, verify=False)
    if r.status_code != 200:
        raise SystemExit('send_to_splunk_hec failed - I am slain!')



class EventPreamble:
    def __init__(self):
        self.local_ip = ()
        self.event_list = ()
        self.this_script = ()
        self.this_pid = ()
        

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        local_ip = str(local_ip)
        return(local_ip)

    #def get_script(self):
    #    this_script = os.path.basename(__file__)
    #    return(this_script)

    #def get_pid(self):
    #    this_pid = os.getpid()
    #    this_pid = str(this_pid)
    #    return(this_pid)

    def create_event_base(self,this_pid,this_script):
        friendly_timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S.%f")
        #this_script = os.path.basename(__file__)
        #this_pid = os.getpid()
        #this_pid = str(this_pid)
        this_ip = get_local_ip()
        script_and_pid = [this_script, "[", this_pid, "]:"]
        script_and_pid_and_colon = ''.join(script_and_pid)
        event_list=[friendly_timestamp, this_ip, script_and_pid_and_colon]
        return(event_list)    