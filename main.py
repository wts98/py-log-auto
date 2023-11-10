#!/usr/bin/python3
import os
import subprocess
import argparse
from pathlib import Path
import shutil
import platform
import re
import sys
import magic
verbose=0
# Parser init
parser = argparse.ArgumentParser(prog='Linux Log Forensic Automation', description='Optional app description')
parser.add_argument('Run_OP', nargs='?', type=int, help='Run_OP stands for the three operations to do (in the range of 1-3), 1 for Log gathering, 2 for Log Classification (if a log dir was found), 3 for Log summary')
# Verbosity !! need not to add second argument to this
parser.add_argument('-v', '--verbose', action="count", help='enable verbose outputting for debug', default=0, dest='vb') 
# Custom Path, variable $c should be parsed and taken in Gathering 
parser.add_argument('-c', '--path', type=str, nargs='?', help='custom path to logs, format should be "/PATH/TO/LOG", absolute path are recommended.', dest='ptl')
args = parser.parse_args()
print(args.Run_OP, " is the running option I think")

if 1 <= args.Run_OP <= 3: #Check if run option is out of 1-3 range
    if args.Run_OP == 1:
        print("Log Gathering Will be carried out") 
        destination = Path.cwd()
        # func(Log Gathering)
        ### Log Check ? ###
        # Read line from file(
        if args.ptl is None:
            #Read default route (/var/log/*/*.log)
            st_pt = Path('/var/log/') # starting poing
            for pathentry in st_pt.iterdir():
                check = open(pathentry.strip(), 'rb').read() #check all text encoding of file
                m = magic.open(magic.MAGIC_MIME_ENCODING)
                m.load()
                encoding = m.buffer(check)
                if ((encoding == 'utf-8') or  (encoding == 'us-ascii')): #if matched either, the file is valid and readable
                    shutil.copy2(pathentry.strip(), destination)
        else:
            if not os.path.exists(args.ptl):
                print(args.ptl," is not valid")
            else:
                file = open(args.ptl, 'r') #Start of Custom Path
                print(args.ptl," is the given custom path to list of logs.")
                filelines = file.readlines()
                for le in file:
                    check = open(le.strip(), 'rb').read() #check all text encoding of file
                    m = magic.open(magic.MAGIC_MIME_ENCODING)
                    m.load()
                    encoding = m.buffer(check)
                    if ((encoding == 'utf-8') or  (encoding == 'us-ascii')): #if matched either, file is valid and readable // Should I do functional programming instead?
                        shutil.copy2(le.strip(), destination) #secure copy to current dir
                    else:
                        print(le.strip()," is not valid path")
        initso= subprocess.Popen(['ps', '-p', '1', '-o' 'comm='], stdout=subprocess.PIPE) # Get name of 1st ps (i.e. the name of the init system)
        init = initso.stdout.read()
        if init == 'systemd': #check if init system is systemd
            srvs = open("srvs.lst", "w")
            subprocess.call(['systemctl', 'list-units', '--type=service'], stdout=srvs) #Get all services in systemd style
            syslog = open("syslog.log", "w")
            subprocess.call(['journalctl', '--no-pager'], stdout=syslog) #Get all journal logs in systemd style
        elif init == 'sysvinit':
            srvs = open("srvs.lst", "w")
            subprocess.call([ 'service', '--status-all'], stdout=srvs) #Get all service in Sysvinit style
            shutil.copy2('/etc/auth.log', destination)
            #shutil.copy2 ##syslog copy?
        else:
            print(init, " is not supported by this program for now!!")

        shutil.copy2('/etc/os-release', destination)
        
#To do: loop all path in for loop with same args
#### Log Check END ###
    elif args.Run_OP == 2:
        print("Running Log Classification")
    # func(Log Classification)
    elif args.Run_OP == 3:
        print("Running Log Summarization")
    # func(Log Summarization)
    else:
        print(le ," is Invalid Option!!!")

#verbose=args.vb #extract verbose option
#print(verbose) #PoC
#custom=args.vb #extract custom path to list of logs

# test if custom path is valid#

#if verbose == 0 ## Start of ifelse hell to enable verbosity##
#if custom == none; do use normal wl
##### Test of verbosity level (may not be implemented at last)
#for c in ['', '-v', '-v -v', '-vv', '-vv -v', '-v -v --verbose -vvvv']:
#    print(parser.parse_args(c.split()))

###

######## END OF OPTION ###########
#filelist ['file1', 'file2', 'file3'] #to do: from wordlist add file to filelist[]
#while True:
#    list1 = []
#    
#    for file in filelist:
#        list1.append(os.path.exists(file))
#
#        if all(list1):
#            break
#        else:
#            time.sleep(6)
#path= '/var/log'
#check_path=os.path.exists(path)
#print(check_path)
#cmd=["find", "/var/log", "-maxdepth", "1", "-not", "-type", "d", "|", "xargs", "ls"]
#cmd=subprocess.Popen["find", "/var/log"]
#return_output = subprocess.check_output(cmd)
#print('Total files of logs of your system are:', return_output.decode("utf-8"))
#Copy and stuff

