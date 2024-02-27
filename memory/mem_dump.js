function dumpMemory() {
    var fullMemoryDump = [];
    var baseAddress = '0x0';
    var pid = Process.getCurrent().pid; 

    Process.enumerateRanges('rw-').forEach(function (range, index) {
        try {
            var bytes = Memory.readByteArray(range.base, range.size);
            fullMemoryDump.push(bytes);
            if (index === 0) {
                baseAddress = range.base.toString(16);
            }
        } catch (e) {
            console.error(e.message);
        }
    });

    // Concatenate all byte arrays into a single buffer
    var totalSize = fullMemoryDump.reduce((acc, bytes) => acc + bytes.byteLength, 0);
    var dumpBuffer = new ArrayBuffer(totalSize);
    var dumpView = new Uint8Array(dumpBuffer);
    var offset = 0;
    fullMemoryDump.forEach(function (bytes) {
        dumpView.set(new Uint8Array(bytes), offset);
        offset += bytes.byteLength;
    });

    // Write the complete memory dump to a file
    const filePath = `pid_${pid}_${baseAddress}_dump.bin`; 
    const file = new File(filePath, "wb");
    file.write(dumpBuffer);
    file.close();

    console.log(`Full memory dump saved to ${filePath}`);
}

dumpMemory();
