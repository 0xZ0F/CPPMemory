# Windows Process Hacking Library

## Patching: 
**The patching functions will write to memory.**  
NOTE: When `VirtualProtectEx()` is used a PAGE_GUARD gets triggered. If you need more stealth you will have to come up with your own method until I implement one.
* `PatchEx()`: Writes given bytes to given address.
  * This function doesn't return anything.
  * `hProc` is a handle to a process.
  * `dst` is an address in the target process to write to.
  * `bytes` is data to be written by the function.
  * `size` is how many bytes to write.
* `NopEx()`: Writes a specified number of NOP instructions at the given address. 
  * This function doesn't return anything.
  * `hProc` is a handle to a process.
  * `dst` is an address in the target process to write to.
  * `size` is how many bytes/NOPs to write. (One NOP is one byte).

## Process:
**The process functions are used to gather information about processes, modules, etc.**  
* `GetProcID()`: Retrieve an ID of a process given its name.
  * This function returns a DWORD containing a process ID.
  * `exeName` is a name of a process/executable.
* `GetModule()`: Retrieve a module given a process ID and the name of a module.
  * This function returns a MODULEENTRY32 structure.
  * `procID` is a process ID.
  * `moduleName` is a name of a module.

## Pattern Scanning:
**The pattern scanning functions are used to scan for patterns within a process.**
Question marks in a mask will account for changes in a binary such as hard-coded addresses determined at runtime.  
* `PatternScanExModule()`: Scans for a given pattern with given mask inside of a given module.
  * This function returns a void pointer (void*) which contains the address where a pattern was found. 
  * `hProc` is a handle to a process.
  * `exeName` is a name of a process/executable.
  * `module` is a name of a module.
  * `pattern` is a pattern to be searched for.
  * `mask` is a mask for a pattern.
* `PatternScanEx()`: Scans for a given patter with a given mask in a given process passed via a process handle.
  * `hProc` is a handle to a process.
  * `begin` is a starting address of a region in memory to be scanned.
  * `end` is an ending address of a region in memory to be scanned.
  * `pattern` is a pattern to be searched for.
  * `mask` is a mask for the pattern.
* `PatternScan()`: Scans given bytes for a given pattern. This is used by `PatternScanEx()` and `PatternScanExModule()` which pass a chunk of memory to this funciton to be scanned.
  * `base` contains a pointer to bytes to be scanned.
  * `size` is a size of a buffer to be scanned.
  * `pattern` is a pattern to be searched for.
  * `mask` is a mask for the pattern.

## Auto:
**The auto functions are wrappers for common tasks so you don't have to write everything yourself constantly.**
* `AutoWriteToAddress()`: Writes given bytes to given address. 
  * `procName` is a name of a process.
  * `dst` is an address in the target process to write to.
  * `bytes` is data to be written by the function.
  * `size` is how many bytes to write. Setting this argument to 0 will make the function compute the size automatically. This argument defaults to 0.
* `AutoWriteToOffset()`: Writes given bytes to a given offset from a base address.
  * `procName` is a name of a process.
  * `modName` is a name of a module.
  * `offset` offset from an address to be written to.
  * `bytes` is data to be written by the function.
  * `size` is how many bytes to write. Setting this argument to 0 will make the function compute the size automatically. This argument defaults to 0.
* `AutoWriteToPattern`: Writes given bytes to a given address found via a pattern scan.
  * `procName` is a name of a process.
  * `modName` is a name of a module.
  * `pattern` is a pattern to be searched for.
  * `mask` is a mask for the pattern.
  * `bytes` is data to be written by the function.
  * `size` is how many bytes to write. Setting this argument to 0 will make the 