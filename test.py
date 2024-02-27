import frida
import sys
import os
import psutil
import pefile
import argparse
import json
import webbrowser
import threading
import time
import hashlib
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Hooked functions
general_hooks =  ['LoadLibrary', 'GetProcAddress', 'CreateMutex']
process_hooks =  ['CreateProcessInternalW', 'OpenProcess', 'VirtualAllocEx', 'VirtualProtect']
file_hooks =     ['CreateFile', 'WriteFile', 'MoveFile', 'CopyFile', 'DeleteFile']
registry_hooks = ['RegCreateKey', 'RegOpenKey', 'RegQueryValueEx', 'RegSetValueEx', 'RegDeleteValue']
internet_hooks = ['InternetOpenUrl', 'GetAddrInfo']

report = {
	"processes": {},

	"files": {
		"created": [
		],
		"modified": [
		],
		"deleted": [
		],
		"moved": [
		],
		"copied": [
		]
	},

	"commands": [
	],


	"network": {
		"urls" : [
		],
		"dns": [
		]
	},

	"registry": {
		"set": [
		],
		"queried": [
		],
		"deleted": [
		]
	},

	"general": {
		"mutexes": [
		],

		"imports": [
		]
	},
	"sample": {
		"sha256": "",
		"sha": "",
		"type": "",
		"name": "",
	}
}

##########################################################################################################

# Globals
sample_pid = 0
current_pid = 0

phandle_to_pid = {}     # map process handle to process id
pid_to_data = {}
injected_procs = []
proc_data = {
	0: {'children': []}	# parent processes
}

fhandles_to_path = {}   # map file handle to file path
created_files  = set()
modified_files = set()
deleted_files  = set()
moved_files    = []
copied_files   = []


rhandle_to_key = {}     # map registry key handle to key name
set_regs     = set()
queried_regs = set()
deleted_regs = set()

accesed_urls = set()
dns_domains  = set()

executed_commands = set()
dynamic_imports = set()
mutexes         = set()

##########################################################################################################
def on_mem_message(message, data):
    print("[%s] => %s" % (message, data))


def perform_memory_dump(pid, session):
	print(f"[!] Dumping memory of pid : {pid}")
	with open('memory/mem_dump.js', 'r') as file:
		memory_dump_script = file.read()

	dump_script = session.create_script(memory_dump_script)
	dump_script.on('message', on_mem_message)
	dump_script.load()  # This will execute the memory dumping in the target process

def terminate_process_after_timeout(pid):
    """Terminate the process and its children after a specified timeout."""
    parent_process = psutil.Process(pid)
    for child in parent_process.children(recursive=True):
        try:
            child.terminate()
        except:
            pass
    parent_process.terminate()

def get_sha256_hash(file_path):
    with open(file_path, "rb") as f:
        bytes = f.read() # read entire file as bytes
        readable_hash = hashlib.sha256(bytes).hexdigest()
        return readable_hash

# handle process activity hooks
def handle_process(payload):
	if(payload['hook'] == 'CreateProcessInternalW'):
		phandle_to_pid[payload['handle']] = payload['pid']
		if(payload['cmd'] != None):
			executed_commands.add(payload['cmd'])
		else:
			executed_commands.add(payload['app'])

	elif(payload['hook'] == 'OpenProcess'):
		phandle_to_pid[payload['handle']] = payload['pid']
		
	elif(payload['hook'] == 'VirtualProtect'):
		print('[!] VirtualProtect called. dumping memory...')

	elif(payload['hook'] == 'VirtualAllocEx'):
		injected_pid = phandle_to_pid.get(payload['handle'])
		if injected_pid != None:
			if(injected_pid in proc_data):    # like in process hollowing
				proc_data[injected_pid]['injected'] = True
			else:    # like in classic process injection
				proc_data[injected_pid] = {
					"name": psutil.Process(injected_pid).name(),
					"injected": True,
					"children": []
				}
				proc_data[current_pid]["children"].append(injected_pid)

##########################################################################################################

# handle file activity hooks
def handle_file(payload):
	if(payload['hook'] == 'CreateFile'):
		fhandles_to_path[payload['handle']] = (payload['path'], payload['new']);

	elif(payload['hook'] == 'WriteFile'):
		fdata = fhandles_to_path.get(payload['handle'])
		if fdata != None:
			path, new = fdata
			if new:
				created_files.add(path)
			elif path not in created_files:
				modified_files.add(path)

	elif(payload['hook'] == 'DeleteFile'):
		deleted_files.add(payload['path'])

	elif(payload['hook'] == 'MoveFile'):
		moved_files.append({"from": payload['oldpath'], "to": payload['newpath']})

	elif(payload['hook'] == 'CopyFile'):
		copied_files.append({"from": payload['oldpath'], "to": payload['newpath']})

##########################################################################################################

# handle registry activity hooks
def handle_registry(payload):
	if(payload['hook'] in ['RegCreateKey', 'RegOpenKey']):
		rhandle_to_key[payload['handle']] = payload['regkey']
	else:
		key = rhandle_to_key.get(payload['handle'], "")
		val = (payload['regvalue'] if payload['regvalue'] != None else "(Default)")
		regvalue = (key + '\\' + val).replace('\\\\', '\\')
		if(regvalue[0:4] != 'HKEY'): return

		if(payload['hook'] == 'RegSetValueEx'):
			set_regs.add(regvalue)
		elif(payload['hook'] == 'RegQueryValueEx'):
			queried_regs.add(regvalue)
		elif(payload['hook'] == 'RegDeleteValue'):
			deleted_regs.add(regvalue)

##########################################################################################################

# handle internet activity hooks
def handle_internet(payload):
	if(payload['hook'] == 'InternetOpenUrl'):
		accesed_urls.add(payload['url'])
	elif(payload['hook'] == 'GetAddrInfo'):
		if('.' in payload['domain']):
			dns_domains.add(payload['domain'])

##########################################################################################################

# handle general activity hooks
def handle_general(payload):
    if payload['hook'] == 'GetProcAddress' and all(key in payload for key in ['func', 'args', 'ret_val', 'pid']):
        func_call = {
            'function': payload['func'],
            'arguments': payload['args'],
            'return_value': payload['ret_val'],
            'pid': payload['pid']
        }
        func_call_str = json.dumps(func_call)  # Serialize the entire dictionary
        dynamic_imports.add(func_call_str)     # Add serialized string to the set

    elif(payload['hook'] == 'CreateMutex'):
        if(payload['mutex'] != None):
            mutexes.add(payload['mutex'])

##########################################################################################################

# new child process
def _on_child_added(child):
	pid = child.pid
	ppid = child.parent_pid
	name = child.path.split('\\')[-1]
	instrument(pid, ppid, name, 1)

device = frida.get_local_device()
device.on("child-added", _on_child_added)

def on_message(message, data):
    if(message['type'] == 'error'): return

    payload = message['payload']

    if(payload['hook'] in general_hooks):
        handle_general(payload)
    elif(payload['hook'] in process_hooks):
        handle_process(payload)
    elif(payload['hook'] in file_hooks):
        handle_file(payload)
    elif(payload['hook'] in registry_hooks):
        handle_registry(payload)
    elif(payload['hook'] in internet_hooks):
        handle_internet(payload)
	
def on_detached(message, data):
	print("The process has terminated!")
	sys.exit()

##########################################################################################################

def instrument(pid, ppid, name, is_spawned):
	global sample_pid
	process = psutil.Process(pid)
	name = process.name()  # This gets the process name
	exe_path = process.exe()  # This gets the full path of the executable
	cmdline = ' '.join(process.cmdline())  # This gets the command line arguments
	sha256 = ''
	if exe_path:
		sha256 = get_sha256_hash(exe_path)
	else:
		sha256 = ''
        
	if cmdline:
		executed_commands.add(cmdline)
        
	current_pid = pid
	sample_pid = pid
	proc_data[pid] = {
		"name": name,
		"path": exe_path,  # Full path of the executable
		"cmdline": cmdline,  # Command line arguments
		"sha256": sha256,
		"injected": False,
		"children": []
	}
	proc_data[ppid]["children"].append(pid)

	session = device.attach(pid)
	session.enable_child_gating()  # follow child processes

	script_js = ""
	for root, _, files in os.walk('hooks'):
		for file in files:
			hook_script = os.path.join(root, file)
			with open(hook_script) as f:
				script_js += f.read()

	script = session.create_script(script_js)
	script.on('message', on_message)
	session.on('detached', on_detached)
	script.load()
	#perform_memory_dump(pid, session)
	if is_spawned:
		device.resume(pid)
        



##########################################################################################################

def get_pefile_info(file_path):
    try:
        pe = pefile.PE(file_path)
        is_dll = hasattr(pe, 'OPTIONAL_HEADER') and \
                 pe.OPTIONAL_HEADER.Subsystem == pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_WINDOWS_GUI']
        exported_funcs = [exp.name.decode() for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols if exp.name] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else []
        return is_dll, exported_funcs
    except:
        return None, []

def spawn_process(executable, args):
    is_dll, exports = get_pefile_info(executable)
    if is_dll and exports:
        # Using rundll32.exe to execute the DLL with the first exported function
        rundll32_path = "C:\\Windows\\System32\\rundll32.exe"
        rundll32_args = f"{executable},{exports[0]}"
        return device.spawn([rundll32_path] + [rundll32_args] + args)
    else:
        # Directly spawning the executable with its arguments
        return device.spawn([executable] + args)


# Argument parsing
parser = argparse.ArgumentParser(description="HawkEye Dynamic Analysis Tool")
parser.add_argument("--path", nargs='+', help="Executable path and arguments")
parser.add_argument("--pid", type=int, help="Process PID")

args = parser.parse_args()
device = frida.get_local_device()

if args.path:
    executable = args.path[0]
    exec_args = args.path[1:]  # Arguments for the executable
    pid = spawn_process(executable, exec_args)
    path = os.path.basename(executable)
    instrument(pid, 0, path, 1)
elif args.pid:
    instrument(args.pid, 0, "", 0)
else:
    parser.print_help()
    sys.exit()

# Start the timer thread
time.sleep(300)
#terminate_process_after_timeout(sample_pid)

#input("Analysis Started: Press Enter to kill it at any time!\n\n")
print("Analysis Finished!")
# frida.kill(pid) # or maybe loop through processes

##########################################################################################################

report["processes"] = proc_data

report["files"]["created"]  = list(created_files)
report["files"]["modified"] = list(modified_files)
report["files"]["deleted"]  = list(deleted_files)
report["files"]["moved"]    = moved_files
report["files"]["copied"]   = copied_files

report["registry"]["set"]     = list(set_regs)
report["registry"]["queried"] = list(queried_regs)
report["registry"]["deleted"] = list(deleted_regs)

report["network"]["urls"] = list(accesed_urls)
report["network"]["dns"]  = list(dns_domains)

report["general"]["commands"] = list(executed_commands)
report["general"]["imports"]  = list(dynamic_imports)
report["general"]["mutexes"]  = list(mutexes)

os.chdir('report')
if not os.path.exists('output'):
    os.makedirs('output')
with open(os.path.join('output', 'data.json'), 'w') as f:
	json.dump(report, f)

##########################################################################################################

server_address = ('', 1337)
httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)

server_thread = threading.Thread(name='background', target=httpd.serve_forever)
server_thread.start()

print('Starting a web server...')
time.sleep(3)	# sleep until the server starts
webbrowser.open('127.0.0.1:1337', new=2)   # open in a new tab

input("Web server started: Press Enter to exit!\n\n")
httpd.shutdown()	# kill the server