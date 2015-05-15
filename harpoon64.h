/*

			 harpoon64 (0.1.1)
		x64 hooking library

				---

	harpoon64 is the x64 version
	of harpoon, and is designed
	to provide a lightweight and
	stable function hooking on
	OS X x64.

Special thanks to: @qwertyoruiop (for Haema library and for being a cool guy.)
rentzsch (for mach_override.)

*/

/* DEVELOPMENT VERSION */
// keep in mind that this version is subject to
// changes. And its buggy as fuck.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <mach/mach_init.h>
#include <mach/vm_map.h>
#include <mach/vm_statistics.h>
#include <sys/mman.h>

#include <CoreServices/CoreServices.h>

#include "udis86.h"

#ifdef __i386__ // one day ill merge harpoon and h64, but today's not the day.
	#define ERR_ARCH_NOT_SUPPORTED
#endif

int __throw_hook(void *function, void *replacement, void **origFunc, unsigned char *restorePtr);
int __restore(void *function, unsigned char *restorePtr);

Boolean eatKnownInstructions(unsigned char *code, uint64_t *newInstruction,int *howManyEaten, char *originalInstructions, int *originalInstructionCount, uint8 *originalInstructionSizes);
