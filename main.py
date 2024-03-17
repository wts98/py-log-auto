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
            matching_lines.append(line)
    return matching_lines

def fsstat(le):
    # Simple File Metadata function
    npath= Path(le)
    #cts=time.ctime(npath.stat().st_ctime) // tampered by copytree()j
    mts=time.ctime(npath.stat().st_mtime)
    ats=time.ctime(npath.stat().st_atime)
    cuser=getpwuid(npath.stat().st_uid).pw_name
    fileattr.write(str(le)+","+ str(mts) + "," + str(ats) + "," + str(cuser) +"\n")


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
    #PART 1 START
        users= [entry.name for entry in Path('/home').iterdir() if entry.is_dir()]

        destination=Path.cwd()/"Logs"
        destination.mkdir(parents=True, exist_ok=True)
        services = subprocess.getoutput('systemctl list-unit-files -t service --full --all --plain --no-legend').splitlines()

        output = subprocess.check_output(['rsyslogd', '-v'], universal_newlines=True)
        config_file_line = re.search(r'Config file:\s+(.+)', output)



        log_name_regex = re.compile(r'((.|_)(log|err|out)$|log)')

        service_names = []
        with open("file.attr.csv", "a") as fileattr:
            fileattr.write("File Original Path"+","+"Modified Time"+","+"Last Access Time"+","+"File Creator"+"\n")
            if config_file_line:
                config_file_path = config_file_line.group(1)
                print(f"rsyslog.conf file found at: {config_file_path}")

                uncommented_lines = extract_uncommented_lines(config_file_path)

                pattern = r'^\S+\s+/.+' #pattern to find path in all/most configuration file

                matching_lines = extract_lines_by_pattern(uncommented_lines, pattern)

                #Preconfigurated Rsyslogd config lines:
                print("The syslog path configuration of this system running on rsyslogd is: ")
                for line in matching_lines:
                    pathentry=line.split()[1]
                    fsstat(pathentry)
                    shutil.copy2(pathentry, destination)
                    #sp.writelines(str(pathentry)+"\n")

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
                        encoding = m.buffer(check)
                        if encoding in ['utf-8', 'us-ascii']: #if matched either, the file is valid and readable
                            service_name = None
                            for service in services:
                                if service in str(pathentry):
                                    service_name = service.split('.')[0]
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
                                fsstat(pathentry)
                                src.writelines(f"{pathentry}\n")
                                print(f"Copied {pathentry} to {destination_path}")
                            else:
                                print(f"Skipped {pathentry} because its name does not match the regex")
                            #parent_dirs = list(pathentry.parents)
                            #parent_dirs.reverse()  # Reverse the list to get from top-most parent to immediate parent
                            #filename = f"{parent_dirs[0].name}_{pathentry.name}"
                            #if parent_dirs[0].name != 'log':
                            #    shutil.copy2(pathentry, destination/parent_dirs[0]/ filename)
                            #else:
                            #    shutil.copy2(pathentry, destination)
                            #shutil.copytree(pathentry, destination)


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
                            fsstat(hist_file_path)
                            src.write(f"{hist_file_path}\n")
                            shutil.copy2(hist_file_path, usrdir) #be reminded that all history file are HIDDEN.
        #PART 1 FINISHED
    elif args.Run_OP == 2:
        print("Running log Classification")
        cur = Path.cwd()
        pathcheck=0
        paths =[cur/'Logs', cur/'SourceList.txt', cur/'file.attr.csv', cur/'userlist/'] #requested paths
        for path in paths:
            if path.exists():
                pathcheck += 1
                if pathcheck == 4:
                    print("All required documentation exist, now it will restart")
            else:
                print(f"Required {paths[path]} not found, please redo the collection")
    else:
        print("Value more or eq to 3, invalid now")