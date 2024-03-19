import frida
import sys
import pefile
import psutil
import json
import time
import hashlib
import os
import threading
import time
import argparse

# Global variable to keep track of active processes

report = {
	"processes": {},
    	"general": {
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


file_writes = {}
handle_to_filename = {}

active_sessions = []
process_hooks =  ['CreateProcess', 'CreateProcessW', 'CreateProcessInternalW', 'OpenProcess']

sample_pid = 0
current_pid = 0

phandle_to_pid = {}     # map process handle to process id
pid_to_data = {}
injected_procs = []
proc_data = {
	0: {'children': []}	# parent processes
}
executed_commands = set()

js_code = """
'use strict';
var pOpenProcess = Module.findExportByName(null, "OpenProcess");
Interceptor.attach(pOpenProcess, {
    onEnter: function(args) {
        // Assuming the desired access rights (args[0]) could be of interest, you might also capture it
        this.desiredAccess = args[0].toInt32();
        this.pid = args[2].toInt32();
    },
    onLeave: function(retval) {
        // Sending structured message for consistency with CreateProcess handling
        send({
            action: "OpenProcess",
            detail: {
                handle: retval.toInt32().toString(), // Convert handle to string
                pid: this.pid.toString(), // Convert PID to string
                desiredAccess: this.desiredAccess.toString() // Convert desired access to string if needed
            }
        });
    }
});

Interceptor.attach(Module.findExportByName("kernel32.dll", 'CreateProcessW'), {
    onEnter: function(args) {
        // Capture the application name and command line arguments
        this.applicationName = args[0].isNull() ? "NULL" : args[0].readUtf16String();
        this.commandLine = args[1].isNull() ? "NULL" : args[1].readUtf16String();
    },
    onLeave: function(retval) {
        // The process creation was successful if retval is not 0
        if (retval.toInt32() !== 0) {
            // Assuming the PROCESS_INFORMATION structure is passed as the 5th argument
            // Retrieve the process ID from the PROCESS_INFORMATION structure
            var processInfo = args[4];
            var pid = processInfo.add(4).readU32(); // PID is at offset 4 in PROCESS_INFORMATION

            // Send collected details back to the Python script
            send({
                action: "CreateProcess",
                detail: {
                    applicationName: this.applicationName,
                    commandLine: this.commandLine,
                    pid: pid.toString()
                }
            });
        }
    }
});
var pCreateProcessInternalW = Module.findExportByName(null, "CreateProcessInternalW");
Interceptor.attach(pCreateProcessInternalW, {
    onEnter: function(args) {
        this.app = args[1].readUtf16String();
        this.cmd = args[2].readUtf16String();
        if (null == this.app)
            this.app = "c:\\windows\\system32\\cmd.exe";
        this.procinfo = args[10];
    },
    onLeave: function(retval) {
        send({
            action: "CreateProcess", // Use a consistent action name for handling in Python
            detail: {
                applicationName: this.app,
                commandLine: this.cmd,
                pid: this.procinfo.add(2 * Process.pointerSize).readPointer().toInt32().toString(), // Convert PID to string
            }
        });
    }
});

// Hook VirtualProtect
Interceptor.attach(Module.findExportByName(null, 'VirtualProtect'), {
    onEnter: function(args) {
        this.address = args[0];
        this.size = args[1].toInt32();
        this.newProtect = args[2];
    },
    onLeave: function(retval) {
        if (this.newProtect.toInt32() == 0x40) { // PAGE_EXECUTE_READWRITE
            send({
                action: "VirtualProtect",
                detail: {
                    address: this.address.toString(),
                    size: this.size
                }
            });
            var buf = Memory.readByteArray(this.address, this.size);
            send({
                action: "MemoryDump",
                detail: {
                    address: this.address.toString(),
                    size: this.size
                }
            }, buf);
        }
    }
});

// Hook VirtualAlloc
Interceptor.attach(Module.findExportByName(null, 'VirtualAlloc'), {
    onEnter: function(args) {
        send({
            action: "VirtualAlloc",
            detail: {
                size: args[1].toInt32()
            }
        });
    }
});

// Hook CreateFileA to capture handles
Interceptor.attach(Module.findExportByName(null, 'CreateFileA'), {
    onEnter: function(args) {
        this.filePath = Memory.readCString(args[0]);
    },
    onLeave: function(retval) {
        var handle = retval.toInt32(); // Or toInt64() if you're dealing with a 64-bit application
        send({
            action: "CreateFile",
            detail: {
                filename: this.filePath,
                handle: "0x" + handle.toString(16).toUpperCase() // Convert to hex string
            }
        });
    }
});

// Hook CreateFileW to capture handles
Interceptor.attach(Module.findExportByName(null, 'CreateFileW'), {
    onEnter: function(args) {
        this.filePath = Memory.readUtf16String(args[0]);
    },
    onLeave: function(retval) {
        var handle = retval.toInt32(); // Or toInt64() if you're dealing with a 64-bit application
        send({
            action: "CreateFile",
            detail: {
                filename: this.filePath,
                handle: "0x" + handle.toString(16) // Convert to hex string
            }
        });
    }
});


// Example of hooking WriteFile to monitor file writes
Interceptor.attach(Module.findExportByName(null, 'WriteFile'), {
    onEnter: function(args) {
        this.handle = args[0];
        this.buffer = args[1];
        this.numberOfBytesToWrite = args[2].toInt32(); // Ensure correct data type
    },
    onLeave: function(retval) {
        var data = Memory.readByteArray(this.buffer, this.numberOfBytesToWrite);
        send({
            action: "WriteFile",
            detail: {
                handle: "0x" + this.handle.toString(16) // Consistent with other handle formats
            }
        }, data); // Ensure data is sent as the second argument
    }
});
Interceptor.attach(Module.findExportByName(null, 'CloseHandle'), {
    onEnter: function(args) {
        // args[0] is the handle being closed
        this.handle = args[0];
    },
    onLeave: function(retval) {
        // Only send the message if the handle close operation was successful
        if (retval.toInt32() !== 0) { // Check this condition based on how your target application behaves
            send({
                action: "CloseHandle",
                detail: {
                    handle: "0x" + this.handle.toString(16) // Send the handle in hexadecimal format
                }
            });
        }
    }
});
"""

def get_sha256_hash(file_path):
    with open(file_path, "rb") as f:
        bytes = f.read() # read entire file as bytes
        readable_hash = hashlib.sha256(bytes).hexdigest()
        return readable_hash


# new child process
def _on_child_added(child):
	pid = child.pid
	ppid = child.parent_pid
	name = child.path.split('\\')[-1]
	instrument(pid, ppid, name, 1)

device = frida.get_local_device()
device.on("child-added", _on_child_added)


def on_message(message, data):
    #print(f"Received message: {message}") 
    if message['type'] == 'send':
        action = message['payload']['action']
        details = message['payload']['detail']

        # Convert handle to lowercase when retrieving from the message
        handle = details.get('handle', '').lower()  # Default to empty string and convert to lowercase

        if action == 'CreateFile':
            filename = details['filename']
            print(f"[!] CreateFile called: filename: {filename}, handle: {handle}")
            handle_to_filename[handle] = filename
            if filename not in file_writes:
                file_writes[filename] = b''

        elif action == 'WriteFile':
            if handle in handle_to_filename:
                filename = handle_to_filename[handle]
                print(f"[!] WriteFile called: handle: {handle}, data length: {len(data)}")
                file_writes[filename] += data
            else:
                print(f"Error: Handle {handle} not found in handle mapping upon write.")

        elif action == 'CloseHandle':
            if handle in handle_to_filename:
                filename = handle_to_filename.pop(handle)
                if filename in file_writes and file_writes[filename]:
                    dump_path = os.path.join('extracted', os.path.basename(filename))
                    os.makedirs(os.path.dirname(dump_path), exist_ok=True)
                    with open(dump_path, "wb") as dump_file:
                        dump_file.write(file_writes[filename])
                    print(f"Dumped {filename} to {dump_path}")
                else:
                    print(f"No data to dump for {filename} or file not found in writes.")
            else:
                print(f"Error: Handle {handle} not found in handle mapping upon close.")

        elif action in ['VirtualAllocEx', 'VirtualProtect', 'VirtualAlloc']:
            print("[!] VirtualAlloc called")

        elif action in process_hooks:
            pid = details.get('pid', 'N/A')  # PID of the newly created process
            applicationName = details.get('applicationName', 'N/A')  # Application name
            commandLine = details.get('commandLine', 'N/A')  # Command line arguments

            # Since 'processName' and 'imageFilePath' are not directly provided, adjust accordingly
            # Assuming 'applicationName' serves as the 'processName'/'imageFilePath' in this context
            print(f"[!] CreateProcess called: PID: {pid}, Process Name: {applicationName}, Image File Path: {applicationName}, Command Line: {commandLine}")



def on_detached(message, data):
    print("The process has terminated!")
    sys.exit()

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


    script = session.create_script(js_code)
    script.on('message', on_message)
    session.on('detached', on_detached)
    script.load()
    #perform_memory_dump(pid, session)
    if is_spawned:
        device.resume(pid)


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


if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="DumpStart Dynamic unpacking Tool")
    parser.add_argument("--path", nargs='+', help="Executable path and arguments")
    parser.add_argument("--pid", type=int, help="Process PID")
    parser.add_argument("--time", type=int, help="Timeout" , default=300)

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
    time.sleep(int(args.time))
    #terminate_process_after_timeout(sample_pid)
    #aptured_screenshots.add(capture_screenshot(event_name=f"process_created_{pid}"))
    #input("Analysis Started: Press Enter to kill it at any time!\n\n")
    print("Analysis Finished!")

    report["processes"] = proc_data
    report["general"]["commands"] = list(executed_commands)
    # frida.kill(pid) # or maybe loop through processes
    print(json.dumps(report))

