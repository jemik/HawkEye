var vpExportAddress = Module.getExportByName("kernel32.dll", "VirtualProtect");
Interceptor.attach(vpExportAddress,
{   
	onEnter: function(args)
	{


		var vpAddress = args[0];
		var vpSize = args[1].toInt32();
		var vpProtect = args[2];
		console.log("[+] VirtualProtect called: " + vpAddress + ", size: " + vpSize + " and protection: " + vpProtect);
		console.log(hexdump(vpAddress));
		
		if (vpAddress.readAnsiString(2) == "MZ")
		{
			console.log("[+] MZ header at address: " + vpAddress);
			var exe = vpAddress.readByteArray(vpSize);

			var filename = vpAddress + "dumped.exe";
			var file = new File(filename, "wb");
			file.write(exe);
			file.flush();
			file.close();
			console.log("[+] Dumped executable: " + filename);

			
			send({
                'hook': 'VirtualProtect',
				'api_call': "VirtualProtect called: " + vpAddress + ", size: " + vpSize + " and protection: " + vpProtect,
				'mz_header': vpAddress.readAnsiString(2),
				'dumped_exe': filename
			});

		}

	}
});