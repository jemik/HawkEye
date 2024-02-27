/*
FARPROC GetProcAddress(
  HMODULE hModule,
  LPCSTR  lpProcName
);
*/
var pGetProcAddress = Module.findExportByName(null, "GetProcAddress");

Interceptor.attach(pGetProcAddress, {
    onEnter: function (args) {
        this.hModule = args[0];
        this.lpProcName = args[1].readUtf8String();
        // Resolve the module name using the handle if possible
        var module = Process.findModuleByAddress(this.hModule);
        this.moduleName = module ? module.name : "unknown";
        this.fullNotation = this.moduleName + "! " + this.lpProcName;
    },
    onLeave: function (retval) {
        send({
            'hook': 'GetProcAddress',
            'func': this.fullNotation,
            'args': {
                'hModule': this.moduleName,
                'lpProcName': this.lpProcName
            },
            'ret_val': retval.toString(),
            'pid': Process.id
        });
    }
});


/*
HANDLE CreateMutexW(
  LPSECURITY_ATTRIBUTES lpMutexAttributes,
  BOOL                  bInitialOwner,
  LPCWSTR               lpName
);
HANDLE CreateMutexExW(
  LPSECURITY_ATTRIBUTES lpMutexAttributes,
  LPCWSTR               lpName,
  DWORD                 dwFlags,
  DWORD                 dwDesiredAccess
);
*/
function instrumentCreateMutex(opts) {
	if(opts.ex) {
		var pCreateMutex = opts.unicode ? Module.findExportByName(null, "CreateMutexExW")
                                    	: Module.findExportByName(null, "CreateMutexExA");
    } else {
		var pCreateMutex = opts.unicode ? Module.findExportByName(null, "CreateMutexW")
                                    	: Module.findExportByName(null, "CreateMutexA");
    }
	Interceptor.attach(pCreateMutex, {
		onEnter: function(args) {
			if(opts.ex) {
				var mutex = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			} else {
				var mutex = opts.unicode ? args[2].readUtf16String() : args[2].readUtf8String();
			}
			send({
				'hook': 'CreateMutex',
				'mutex': mutex
			});
		}
	});
}
instrumentCreateMutex({unicode: 0, ex: 0});
instrumentCreateMutex({unicode: 1, ex: 0});
instrumentCreateMutex({unicode: 0, ex: 1});
instrumentCreateMutex({unicode: 1, ex: 1});