# harpoon (x64)
Very simple runtime hooking library for OS X.

## Warning
This library is still in early alpha, and I am still creating basically everything. Expect bugs and strange behavior while using this.

## How to implement
This branch works on x64, for x86 see the `master` branch. There is one hooking function:
* `__throw_hook(void *, void *, void**, unsigned char *)` : Throws an hook to the function defined in the first param, replacing the implementation with the function defined in the second. The third is an optional pointer to a pointer, which (if not `NULL`) will contain an address to call the original function __(see note below!)__. The fourth is an optional argument which (if not `NULL`) will contain the function's stolen bytes. Upon calling `__restore()`, the stolen bytes will be thrown back into the original function. Basically used to de-hook the hook. * `__restore(void *, unsigned char *)` : De-hooks the hook. First parameter is the hooked function, second is a pointer to the stolen bytes. 

## How to inject
You can use every runtime injecting code to shoot the `dylib`. However, note that `harpoon` doesn't have an injecting routine, so it must be external. If you don't care about runtime injection, go for a classical `DYLD_INSERT_LIBRARIES` and launch the program. Remember to force the flat namespace! Example:
  
      DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=libTest.dylib ./test

## Known issues
These are the known issues with the library.

* **`void **origFunc` may be problematic in certain cases.** –– The third parameter of the `__throw_hook` function may cause some problems. In some cases (not always) it may chop off important parts of the code (ex. LEAs for `printf()`s/`puts()`es). The instructions are actually executed in the backup prologue, but they are lost while jumping back to the original implementation.
This is due to the long size of the shellcode, which forces a very large backup.
I am thinking of a workaround, but for now just use the `__restore()` function. Or if it works in your case, no other known problems w/ `**origFunc`.

## Updates
I will add more hooking methods and fix existing. The `**origFunc` fix is a priority for now.
