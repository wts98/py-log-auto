#!/usr/bin/python3
import os #system + shell + path , dangerous 
import subprocess #subshell, dangerous too
import argparse #input
from pathlib import Path
import shutil #secure copy
import re #regex
import magic #magic attr
import glob #file only unix matching
import logging
import time
from pwd import getpwuid
def fsstat(le):
    #Check if log itself has been tampered with!!
    npath= Path(le)
    #cts=time.ctime(npath.stat().st_ctime) // tampered by copytree()j
    mts=time.ctime(npath.stat().st_mtime)
    ats=time.ctime(npath.stat().st_atime)
    #ctr=npath.stat().st_creator
    cuser=getpwuid(npath.stat().st_uid).pw_name
    #print('Created time ', cts)
    fileattr.writelines("File Original Path: "+str(pathentry)+","+"Modified Time:"+ str(mts) + "," + str(ats) + "," + str(cuser) +"\n")
    

def copytree(src, dst, symlinks = False, ignore = None):
  if not os.path.exists(dst):
    os.makedirs(dst)
    shutil.copystat(src, dst)
  lst = os.listdir(src)
  if ignore:
    excl = ignore(src, lst)
    lst = [x for x in lst if x not in excl]
  for item in lst:
    s = os.path.join(src, item)
    d = os.path.join(dst, item)
    if symlinks and os.path.islink(s):
      if os.path.lexists(d):
        os.remove(d)
      os.symlink(os.readlink(s), d)
      try:
        st = os.lstat(s)
        mode = stat.S_IMODE(st.st_mode)
        os.lchmod(d, mode)
      except:
        pass # lchmod not available
    elif os.path.isdir(s):
      copytree(s, d, symlinks, ignore)
    else:
      shutil.copy2(s, d)

def print_matched_lines(regex, text): #custom regex function to print matched line by line
    lines = text.split('\n')
    for i, line in enumerate(lines, start=1):
        matches = re.findall(regex, line)
        if matches:
            print(f"Line {i}: {line}")
            for match in matches:
                print(f" - Match: {match}")
users= [entry.name for entry in Path('/home').iterdir() if entry.is_dir()]

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

if 1 >= args.Run_OP <= 4: #Check if run option is out of 1-3 range
    initso= subprocess.Popen(['ps', '-p', '1', '-o' 'comm='], stdout=subprocess.PIPE) # Get name of 1st ps (i.e. the name of the init system)
    init = initso.stdout.read()
    if args.Run_OP == 1:
        print("Log Gathering Will be carried out") 
        Logdir=Path(Path.cwd/'Logs')
        Logdir.mkdir(parents=True, exist_ok=True)
        destination = Path.cwd()/"Logs"
        destination.mkdir()
        # func(Log Gathering)
        ### Log Check ? ###
        # Read line from file
        with open("SourcePath.txt", "a") as sp: #Funny thing that list all the copied logs as another, you gussed it, Log/Record!
            if args.ptl is None:
                #Read default route (/var/log/*/*.log)
                st_pt = Path('/var/log/') # starting poing
                fileattr = open("fileattr.csv", "w")
                for pathentry in st_pt.glob('**/*'):
                    if pathentry.is_file():
                        check = open(pathentry, 'rb').read() #check all text encoding of file
                        m = magic.open(magic.MAGIC_MIME_ENCODING)
                        m.load()
                        encoding = m.buffer(check)
                        if ((encoding == 'utf-8') or  (encoding == 'us-ascii')): #if matched either, the file is valid and readable
                            
                            parent_dirs = list(pathentry.parents)
                            parent_dirs.reverse()  # Reverse the list to get from top-most parent to immediate parent
                            filename = f"{parent_dirs[0].name}_{pathentry.name}"
                            if parent_dir.name != 'log':
                                shutil.copy2(pathentry, destination/parent_dir[0]/ filename)
                            else:
                                shutil.copy2(pathentry, destination)
                            #shutil.copytree(pathentry, destination)
                            fsstat(pathentry)
                            sp.writelines(str(pathentry)+"\n")
                        else:
                            print("File", pathentry, "is invalid")
            else:
                if not os.path.exists(args.ptl):
                    print(args.ptl," is not valid")
                else:
                    file = open(args.ptl, 'r') #Start of Custom Path
                    print(args.ptl," is the given custom path to list of logs.")
                    filelines = file.readlines()
                    fileattr = open("fileattr.csv", "w")
                    for le in filelines:
                        check = open(le.strip(), 'rb').read() #check all text encoding of file
                        m = magic.open(magic.MAGIC_MIME_ENCODING)
                        m.load()
                        encoding = m.buffer(check)
                        if ((encoding == 'utf-8') or  (encoding == 'us-ascii')): #if matched either, file is valid and readable // Should I do functional programming instead?
                            shutil.copy2(le.strip(), destination) #secure copy to current dir
                            #Check if log itself has been tampered with!!
                            fsstat(pathentry)
                            sp.writelines(str(pathentry)+"\n")
                        else:
                            print(le.strip()," is not valid path")
        # Get bash history
        if init == 'systemd': #check if init system is systemd
            srvs_enabled = open("srvs.lst.enabled", "w")
            subprocess.call(['systemctl', 'list-unit-files', '--type=service', '--state=enabled'], stdout=srvs_enabled) #Get services in systemd style
            subprocess.call(['sed','-i' , '1d;$d', 'srvs.list.enabled',]) #remove first and last line for text processing
            srvs_enabled.close()
            srvs_disabled = open("srvs.lst.disabled", "w")
            subprocess.call(['systemctl', 'list-unit-files', '--type=service', '--state=disabled'], stdout=srvs_disabled) #Get services in systemd style
            subprocess.call(['sed','-i' , '1d;$d', 'srvs.list.disabled',])
            srvs_disabled.close()
            srvs_static = open("srvs.lst.static", "w")
            subprocess.call(['systemctl', 'list-unit-files', '--type=service', '--state=static'], stdout=srvs_static) #Get services in systemd style
            subprocess.call(['sed','-i' , '1d;$d', 'srvs.list.static',])
            srvs_static.close()
            syslog = open("syslog", "w")
            subprocess.call(['journalctl', '--no-pager'], stdout=syslog) #Get all journal logs in systemd style #default is compatible with other regex
            syslog.close()


        srvs = open("srvs.lst", "w")
        subprocess.call([ 'service', '--status-all'], stdout=srvs) #Get all service in Sysvinit style
        subprocess.call([ 'last', '-f', 'i', 'lastlog'])
        #shutil.copy2('/var/log/auth.log', destination)
        #shutil.copy2 ##syslog copy?
        #shutil.copy2('/var/log/syslog', destination)
        shutil.copy2('/etc/os-release', destination)

        # Obtain command history Per user.
        maindir = Path.cwd/"userlist"
        maindir.mkdir(exist_ok=True)
        histptn = r'^\.[A-Za-z0-9_-]+_history$' #Match all history file format
        #users= [entry.name for entry in Path('/home').iterdir() if entry.is_dir()]
        for d in users:
            dirpath = Path('/home') / d
            files = [entry.name for entry in dirpath.iterdir() if entry.is_file()]
            usrdir = maindir / d
            usrdir.mkdir(exist_ok=True)
            #user_dst= Path.cwd() / 'userlist'
            for fn in files:
                match = re.match(histptn, fn)
                if match:
                    hist_file_path = dirpath / fn
                    fsstat(hist_file_path)
                    shutil.copy2(hist_file_path, usrdir) #be reminded that all history file are HIDDEN.
                    
        
#To do: loop all path in for loop with same args
#### Log Check END ###
    elif args.Run_OP == 2:
        print("Running Log Classification")
        #check if var file is in current directory
        if (Path.cwd()/'Logs').exists() == True:
            #if "syslog.log" and "srvs.st" : (both should exist)
            if (Path.cwd()/"SourcePath.txt").exists() == True and (Path.cwd()/"syslog").exists() == True and (Path.cwd()/"srvs.lst").exists() == True :
                #var is exist
                with open("CaughtLogs.txt", "a") as c:
                    files = [ f for f in os.listdir('./Logs/') if os.path.isdir(f)] #get file name
                    matchtype = r"^.log$"
                    #os.makedirs('./service-list')
                    #os.makedirs('./syslog/')
                    #check init: if sysvinit
                    syslogdir=Path.cwd()/"syslog"
                    syslogdir.mkdir
                    if init == 'systemd':
                        if (Path.cwd()/"syslog.log").exist == True:
                            logging.debug('Systemd JournalLog is found')
                            msrc=Path.cwd()/"syslog.log"
                            shutil.move(msrc, syslogdir)
                        else:
                            logging.debug('Systemd JournalLog is not found')
                            if (Path.cwd()/"").exists == True:
                                logging.debug('')
                        #systemd specific logs
                    
                    if (Path.cwd()/"syslog").exists == True:
                        logging.debug('syslog is found')
                        msrc=Path.cwd()/"syslog"
                        shutil.move(msrc, syslogdir)
                    else:
                        logging.debug('syslog is not fonud')
                    if (Path.cwd()/"auth.log"):
                        logging.debug('auth.log is found')
                        authlog = Path.cwd()/"auth"
                        authlog.mkdir()
                        msrc=Path.cwd()/"auth.log"
                        shutil.move(msrc, authlog)
                    else:
                        logging.debug('auth.log is not found')
       

                    for i in range(len(files)): #Check Presence file? in /var/log?
                        if re.match(r'.*\.log$', files[i]):
                            #match auth?
                            c.writelines(str(i)+"\n")

                        #else:
                            #call back error for mismatched/corrupted log?
                            
                        #match name from srvs and record?

                    # regular expression to identify via file name
            #not exist
        else:
            print('var directory does not exist in the current directory', Path.cwd())
    # func(Log Classification)
    elif args.Run_OP == 3:
        print("Running Log Summarization")
        if (Path.cwd()/'CaughtLogs.txt').exist() == True:
            #collect none-users/disabled accounts which might be used for remote application shell exploitation
            noneuser=[]
            legituser=[]
            with open('/etc/passwd', 'r') as file:
                for line in file.readlines():
                    if "nologin" in line: #\\ /bin/nologin
                        noneuser.append(line.split(':')[0])
                    elif "false" in line: #\\ /bin/false
                        noneuser.append(line.split(':')[0])
                    else: #\\ /bin/{any kinds of interactive or non-interactive shell}
                        legituser.append(line.split(':')[0])
                        # creating 3 list of users which identify
            #statement
            file = open('CaughtLogs.txt', 'r') #Start of Custom Path
            filelines = file.readlines()
        
            for le in filelines:
                if not os.path.exists(le):
                    print(le, " is not found within the previous log collection")
                else:
                    # R E G E X T I M E // re.match from file
                    #VV the following function should able to be reused per each function? But will need to implement how to organize the output as well.
                    #regex string e.g. root, whatever protocol Wit might be #root global matching
                    
                    with open(le, 'r') as file:
                        text=file.read()
                    print_matched_lines(regex, text)
                    ##below are for auth.log
                    with open('/etc/hostname', 'r') as hostnamefile:
                        hostname= hostnamefile.read().rstrip()
                    nonuserprivesc=r"\w\w\w\s\d+\s\d{2}:\d{2}:\d{2}\s" + re.escape(hostname) + r"\s(sudo|login)\:\ssession\sopened\sopened\sfor\suser\sroot\sby$" + re.escape(noneuser[i])    
                    #{Mon} {D} {HH:MM:SS} <hostname> <cmd/util like sudo,login etc>: pam_unix(cmd:session): session opened for user root by <username> (uid=0)
                    useractivity=r"\w\w\w\s\d+\s\d{2}:\d{2}:\d{2}\s" + re.escape(hostname) + r"\s(sudo|login)\:\ssession\sopened\sopened\sfor\suser\sroot\sby$" + re.escape(legituser[i])
                    #{Mon} {D} {HH:MM:SS} <hostname> sudo: pam_unix(sudo:session): session opened for user root by <username> (uid=0)
                    #{Mon} {D} {HH:MM:SS} <hostname> login[pid]: pam_unix(login:session): session opened for user root by <username> (uid=0)
                    #{Mon} {D} {HH:MM:SS} <hostname> login[pid]: pam_unix(login:auth): authentication failure, logname=<service name like postgres uid=<#> euid=<#> tty=tty1 ruser= rhost= user=<username>

                    ##below are for syslog and daemon.log (too low level?)
                    #{Mon} {D} {HH:MM:SS} <hostname> /usr/sbin/cron[pid]: (CRON) {INFO/STARTUP}
                    #{Mon} {D} {HH:MM:SS} <hostname> <service name>: 
                    #{Mon} {D} {HH:MM:SS} <hostname> init: tty<#> main process (#pid) killed by <type of> signal
                    ##below are for vsftpd.log
                    #{WEK} {MON} {D} {HH:MM:SS} {YYYY} [pid ####] CONNECT: Client "<ipv4 ip>"
                    #{WEK} {MON} {D} {HH:MM:SS} {YYYY} [pid ####] [<username>] OK LOGIN: Client "<ipv4 ip>

                    #<username> : TTY=pts/# ; PWD=/path/to/cmd-entry ; USER=root ; COMMAND=/path/to/cmd/binary + arguments

        else:
            print('Missing Log verification and gathering!')


    # func(Log Summarization)
    else:
        print(le ," is Invalid Option!!!")
else:
    print(args.Run_OP ," is Invalid Option!!!")

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

