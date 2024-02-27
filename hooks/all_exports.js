var loadedModules = {}
var resolvedAddresses = {}

function resolveName(dllName, name) {
  var moduleName = dllName.split('.')[0]
  var functionName = moduleName + "!" + name

  if (functionName in resolvedAddresses) {
    return resolvedAddresses[functionName]
  }

  log("resolveName " + functionName);
  log("Module.findExportByName " + dllName + " " + name);
  var addr = Module.findExportByName(dllName, name)

  if (!addr || addr.isNull()) {
    if (!(dllName in loadedModules)) {
      log(" DebugSymbol.loadModule " + dllName);

      try {
        DebugSymbol.load(dllName)
      } catch (err) {
        return 0;
      }

      log(" DebugSymbol.load finished");
      loadedModules[dllName] = 1
    }

    try {
      log(" DebugSymbol.getFunctionByName: " + functionName);
      addr = DebugSymbol.getFunctionByName(moduleName + '!' + name)
      log(" DebugSymbol.getFunctionByName: addr = " + addr);
    } catch (err) {
      log(" DebugSymbol.getFunctionByName: Exception")
    }
  }

  resolvedAddresses[functionName] = addr
  return addr
}
