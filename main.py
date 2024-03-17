#!/usr/bin/python3
import re
import shutil
import subprocess
from pathlib import Path
import magic
import datetime
import time
from pwd import getpwuid
import argparse
import sys
import csv
from grp import getgrgid

# Function to extract uncommented configuration lines
def extract_uncommented_lines(file_path):
    uncommented_lines = []
    with open(file_path, 'r') as conf_file:
        for line in conf_file:
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('$'):
                uncommented_lines.append(line)
    return uncommented_lines

# Function to extract lines matching a specific pattern
def extract_lines_by_pattern(lines, pattern):
    matching_lines = []
    for line in lines:
        if re.search(pattern, line):
            path = line.split()[1]
            if '*' not in path:
                matching_lines.append(line)
    return matching_lines

def fsstat(le):
    # Simple File Metadata function
    npath= Path(le)
    st=npath.stat()
    #cts=time.ctime(npath.stat().st_ctime) // tampered by copytree()j
    mts=time.ctime(st.st_mtime)
    ats=time.ctime(st.st_atime)
    cuser=getpwuid(st.st_uid).pw_name
    cgroup=getgrgid(st.st_gid).gr_name
    cmode=oct(st.st_mode)[-3:]
    print(mts, ats, cuser)
    return le, mts, ats, cuser, cgroup, cmode    



destination = Path.cwd()/"Logs" #Default path
verbose=0
# Parser init
parser = argparse.ArgumentParser(prog='Linux Log Forensic Automation', description='Only supports newer linux distribution running with systemd and using rsyslogd instead of syslog-ng')
parser.add_argument('Run_OP', nargs='?', type=int, help='Run_OP stands for the three operations to do (in the range of 1-3), 1 for Log gathering, 2 for Log Classification (if a log dir was found), 3 for Log summary')
# Verbosity !! need not to add second argument to this
parser.add_argument('-v', '--verbose', type=str, nargs='?', help='enable verbose outputting for debug', default=None, dest='vb') 
# Custom Path, variable $c should be parsed and taken in Gathering 
parser.add_argument('-c', '--path-custom', type=str, nargs='?', default=None, help='custom path to list of logs, format should be "/path/to/logs_txt", absolute path are recommended.', dest='ptl')
parser.add_argument('-y', '--path-yara', type=str, nargs='?', default=None, help='custom path to yara log folder, format should be "/path/to/yara_dir", absolute path are recommended.', dest='pty')
parser.add_argument('-f', '--format', choices=['txt', 'html'], default='txt', dest='fmt', help='Output format for the report (default: txt), html is also the other only option.')
args = parser.parse_args()
#print(args.Run_OP, " is the running option I think")

#root = logging.getLogger()
#handler = logging.StreamHandler(sys.stdout)
#handler.setLevel(vb)
#formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#handler.setFormatter(formatter)
#root.addHandler(handler)

#if vbs == 0:
#    loglevel = None
#elif vbs == 1:
#    loglevel = logging.DEBUG

#logging.basicConfig(level=f"{loglevel}", stream=sys.stdout)


if args.Run_OP in {1,2,3}: #Check if run option is out of 1-3 range
    if args.Run_OP == 1:
        if args.ptl == None:
    #PART 1 START
            users= [entry.name for entry in Path('/home').iterdir() if entry.is_dir()]
            destination.mkdir(parents=True, exist_ok=True)
            services = subprocess.getoutput('systemctl list-unit-files -t service --full --all --plain --no-legend').splitlines()

            output = subprocess.check_output(['rsyslogd', '-v'], universal_newlines=True)
            config_file_line = re.search(r'Config file:\s+(.+)', output)



            log_name_regex = re.compile(r'((.|_)(log|err|out)$|log)')

            service_names = []
            with open("file.attr.csv", "a") as fileattr:
                fileattr.write("File Original Path"+","+"Modified Time"+","+"Last Access Time"+","+"File Creator"+","+"Creator Group"+","+"Creator Mode"+"\n")
                if config_file_line:
                    config_file_path = config_file_line.group(1)
                    print(f"rsyslog.conf file found at: {config_file_path}")

                    uncommented_lines = extract_uncommented_lines(config_file_path)

                    pattern = r'^\S+\s+/.+' #pattern to find path in all/most configuration file

                    matching_lines = extract_lines_by_pattern(uncommented_lines, pattern)

                    #Preconfigurated Rsyslogd config lines:
                    
                                       
                    if len(matching_lines) ==0:
                        print(f"Log path configuration not found in {config_file_path}")
                    else:
                        with open("systemlog.csv", "a") as sysw:
                            sysw.write("File Original Path"+","+"Modified Time"+","+"Last Access Time"+","+"File Creator"+","+"Creator Group"+","+"Creator Mode"+"\n")
                            print("The syslog path configuration of this system running on rsyslogd is: ")
                            for line in matching_lines:
                                pathentry=line.split()[1]
                                print(pathentry)
                                le, mts, ats, cuser, cgroup, cmode=fsstat(pathentry)
                                shutil.copy2(pathentry, destination)
                                sysw.write(f"{le},{mts},{ats},{cuser},{cgroup},{cmode}\n")

                        

                else:
                    print("This machine is either not running on rsyslogd, or rsyslogd.conf configuration file is not fonud in this machine, please consult your system administrator.")

        

                    
                for service in services:
                    service_name = service.split('.')[0]
                    service_names.append(service_name)
                st_pt = Path('/var/log')
                with open("SourceList.txt", "w") as src:
                    srcset=set()
                    #To do: add a new list of whitelisted logs?
                    for pathentry in st_pt.glob('**/*'): #should it be trashed too?
                        if pathentry.is_file() and pathentry not in srcset:
                            srcset.add(pathentry)
                            check = open(pathentry, 'rb').read() #check all text encoding of file
                            m = magic.open(magic.MAGIC_MIME_ENCODING)
                            m.load()
                            encoding = m.buffer(check) #Exclude empty logs, mostly
                            if encoding in ['utf-8', 'us-ascii']: #if matched either, the file is valid and readable
                                service_name = None
                                for service in services:
                                    with open("Service.list", 'a') as srvs:
                                        if service in str(pathentry):
                                            service_name = service.split('.')[0]
                                            srvs.write(f"{service_name}")
                                            break
                                if service_name:
                                    log_name = f"{service_name}_{pathentry.name}"
                                    destination_path = destination / service_name / log_name
                                else:
                                    log_name = pathentry.name
                                    destination_path = destination / pathentry.relative_to(st_pt)
                                if log_name_regex.search(log_name):
                                    destination_path.parent.mkdir(parents=True, exist_ok=True)  # Create the parent directory if it does not exist
                                    shutil.copy2(pathentry, destination_path)
                                    src.writelines(f"{pathentry}\n")
                                    #print(f"Copied {pathentry} to {destination_path}") (debugging)
                                    #print(str(le)+","+ str(mts) + "," + str(ats) + "," + str(cuser) +"\n") (debugging)
                                    le, mts, ats, cuser, cgroup, cmode=fsstat(pathentry)
                                    fileattr.write(f"{le},{mts},{ats},{cuser},{cgroup},{cmode}\n") #E//completely tampered by running on a high privileged user
                                    #auth.log/secure, syslog, kern.log will be tampered
                                else:
                                    print(f"Skipped {pathentry} because its name does not match the regex")
                        #Call Logs Via Commands instead of shutil.copy2:
                        with open("journal.out", "a") as sysdslog: #445M
                            subprocess.call(['journalctl', '--no-pager'], stdout=sysdslog) #Get all journal logs in systemd style #default is compatible with other regex
                        with open("fail_stat.out", "a") as faillog:
                            subprocess.call(['faillog', '-a'], stdout=faillog) #
                        with open("lastlog.out", "a") as lastlog:
                            subprocess.call('lastlog', stdout=lastlog)
                        with open("last.out", "a") as last:
                            subprocess.call(['last',], stdout=lastch)
                                #parent_dirs = list(pathentry.parents)
                                #parent_dirs.reverse()  # Reverse the list to get from top-most parent to immediate parent
                                #filename = f"{parent_dirs[0].name}_{pathentry.name}"
                                #if parent_dirs[0].name != 'log':
                                #    shutil.copy2(pathentry, destination/parent_dirs[0]/ filename)
                                #else:
                                #    shutil.copy2(pathentry, destination)
                                #shutil.copytree(pathentry, destination)

        else:
            if not Path.exists(args.ptl):
                print(f"{args.ptl} is an invalid custom path to list of logs")
                
            else:
                print(f"{args.ptl} will be the list of custom path of logs")
                with open(args.ptl, 'r') as clist:
                    with open("SourceList.txt", "w") as src:
                        with open("file.attr.csv", "w") as fileattr:
                            srcset=set()
                            destination_path.parent.mkdir(parents=True, exist_ok=True)
                            for i in clist:
                                if Path.isfile(i) == True and i not in srcset:
                                    srcset.add(i)
                                    log_name = i.name
                                    destination_path = destination / i.relative_to(st_pt)
                                    check = open(i, 'rb').read() #check all text encoding of file
                                    m = magic.open(magic.MAGIC_MIME_ENCODING)
                                    m.load()
                                    encoding = m.buffer(check) #Exclude empty logs, mostly
                                    if encoding in ['utf-8', 'us-ascii']:
                                        shutil.copy2(i, destination_path)
                                        src.writelines(f"{i}\n")
                                        le, mts, ats, cuser, cgroup, cmode=fsstat(pathentry)
                                        fileattr.write(f"{le},{mts},{ats},{cuser},{cgroup},{cmode}\n")
                                    else:
                                        print(f"{i} is an empty or corrupted.")


        maindir = Path.cwd()/"userlist"
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
                    print(hist_file_path)
                    #fsstat(hist_file_path)
                    #src.write(f"{hist_file_path}\n")
                    shutil.copy2(hist_file_path, usrdir) 
                        
        #PART 1 FINISHED
    elif args.Run_OP == 2:
        print("Running log Classification")
        pathcheck=0
        cur=Path.cwd()
        paths =[cur/'Logs', cur/'SourceList.txt', cur/'file.attr.csv', cur/'userlist'] #requested paths
        pathcheck = sum(path.exists() for path in paths)
        if pathcheck == len(paths):
            print("All required documentation exist")
            #do
            # Read the CSV file as a reference list
            reference_list = []
            hist_reference_list =[]
            with open("metatrace.md",'w') as histtrace:
                with open('file.attr.csv', 'r') as csvfile:
                    reader = csv.reader(csvfile)
                    next(reader)  # Skip the header row
                    for row in reader:
                        reference_list.append([row[0], row[1], row[2], row[3], row[4], row[5]])
                        hist_reference_list.append(Path(row[0]).name)

                # Construct the destination path for each file in the "Logs" directory based on its parent directories
                logs_dir = Path.cwd() / "Logs"
                for ref_file in reference_list:
                    dst_file = logs_dir / ref_file[0].replace('/var/log/', '')
                    if dst_file.exists():
                        # Compare the metadata of the files with the reference list
                        mts = datetime.datetime.fromtimestamp(dst_file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        ats = datetime.datetime.fromtimestamp(dst_file.stat().st_atime).strftime('%Y-%m-%d %H:%M:%S')
                        #cmode = oct(dst_file.stat().st_mode)[-3:]
                        ref_mts = datetime.datetime.strptime(ref_file[1], '%a %b %d %H:%M:%S %Y').strftime('%Y-%m-%d %H:%M:%S')
                        ref_ats = datetime.datetime.strptime(ref_file[2], '%a %b %d %H:%M:%S %Y').strftime('%Y-%m-%d %H:%M:%S')
                        #ref_cmode = int(ref_file[5], 8)
                        if mts != ref_mts or ats != ref_ats :#or cmode != ref_cmode:
                            discrepancy = []
                            if mts != ref_mts:
                                discrepancy.append(f"mtime: {mts} != {ref_mts}")
                            if ats != ref_ats:
                                discrepancy.append(f"atime: {ats} != {ref_ats}")
                            #if cmode != ref_cmode:
                            #    discrepancy.append(f"cmode: {cmode} != {ref_cmode}")
                            print(f"Time metadata discrepancy found for file {dst_file}: {', '.join(discrepancy)}")
                            #histtrace.write(f"{dst_file} : {', '.join(discrepancy)}\n")
                    else:
                        print(f"File {dst_file} not found in Logs directory")
                        # Find all the user history files in the "userlist" directory
                
                userlist_dir = Path.cwd() / "userlist"
                history_file_regex = re.compile(r'^\.[A-Za-z0-9_-]+_history$')
                for user_dir in userlist_dir.iterdir():
                    if user_dir.is_dir():
                        history_file = None
                        for file in user_dir.iterdir():
                            if history_file_regex.match(file.name):
                                history_file = file
                                break

                        if history_file is not None:
                            print(history_file)
                            # Read the user history file and check for matches with the log file names in the CSV file
                            with open(history_file, 'r') as f:
                                for i, line in enumerate(f):
                                    for log_file in hist_reference_list:
                                        if log_file in Path(line).name:
                                            print(f"Match found in user history file {history_file}: {log_file} at line {i+1}")
                                            histtrace.write(f"{i+1};{history_file} : {log_file}\n")
                        else:
                            print("History file not found")

            sysf=Path.cwd()/'Logs'/'System Based Logs'
            sysf.mkdir(parents=True, exist_ok=True)
            pmf=Path.cwd()/'Logs'/'Package Manager Based Logs'
            pmf.mkdir(parents=True, exist_ok=True)
            systemfacing=set()
            pkgmgr=set()
            with open("systemlog.csv", "r") as sysw:
                reader = csv.reader(sysw)
                first_column=[]
                for row in reader:
                    file_path = Path(row[0]).name
                    with open('Package-Manage-Logs.txt', 'a') as pml:
                        for file_path in destination.glob('**/*'):
                            # Check if the file has no parent directory
                            if str(file_path).startswith(str(destination)) and len(file_path.relative_to(destination).parts) == 1:
                                # File has no parent directory
                                print(f'{file_path} has no parent directory')
                                #if file_path != ['dpkg.log', 'dnf.librepo.log, dnf.log, dnf.rpm.log']
                                if file_path in ['auth.log', 'secure', 'kern.log', 'messages', 'syslog', 'boot.log', 'bootstrap.log']:
                                    print(f"{file_path} is being moved")
                                    systemfacing.appends(file_path)
                                    shutil.move(file_path, sysf)
                                elif file_path in ['dpkg.log', 'dnf.librepo.log', 'dnf.log', 'dnf.rpm.log', 'zypper.log']: #Package manager Logs
                                    prnt(f"{file_path} is package manager log")
                                    pkgmgr.appends(file_path)
                                    shutil.move(file_path, pmf)
                                    pml.write(file_path)
                                # Do something with the file
                            # Check if the file has a parent directory that is not equal to destination
                            else:
                                print(f'{file_path} has parent directory {file_path.parent.relative_to(destination)}')
                                #those are services etc
                                # Do something else with the file
                                        



        


        else:
            print(f"Please redo the log collection via `sudo python3 .py 1")
    elif args.Run_OP == 3:
            print("Running Op3")
            systemfacing=[]
            if destination.exists() == True:
                for i in destination.rglob("**/*"):
                    if str(i).startswith(str(destination)) and len(i.relative_to(destination).parts) == 1:
                        systemfacing.append(i)




                        #regexes: cron
                        #MMM DD HH:MM:SS hostname service[pid]:
                        

                        #auth.log
                        #

                        #cron log can be separated, while defaulted to syslog
    
    else:
        print("Invalid optin, exit now")