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

#define kOriginalInstructionsSize 32

#include "harpoon64.h"

size_t eaten;

void _craftJump(char *jmp_shellcode, size_t shellcode_size, void *replacement)
{
    memcpy(jmp_shellcode+2, (const void*)&replacement, sizeof(replacement));
    //printf("%p\n", replacement);
}

/*
*   Description: Restores the original prologue for a chosen function.
*   Parameters:
*     - function    : The target function.
*     - restorePtr  : A ptr to an allocated memory zone, containing the original prologue. Used to restore the original function code.
*/

int __restore(void *function, unsigned char *restorePtr)
{

  assert(function);
  assert(*restorePtr);

  vm_protect(mach_task_self(), (vm_address_t)function, 32, 0, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE);
  memcpy(function, restorePtr, eaten);

  return 0;
}

/*
*   Description: Throws an hook to a chosen function.
*   Parameters:
*     - function    : The target function.
*     - replacement : The replacement function.
*     - origFunc    : A ptr to the original prologue. May be NULL. (Used, if not NULL, to call the original function later)
*     - restorePtr  : A ptr to an allocated memory zone. May be NULL. (Used, if not NULL, to restore the original function later)
*/

int __throw_hook(void *function, void *replacement, void **origFunc, unsigned char *restorePtr)
{

  /*

    VERY IMPORTANT NOTE:
    Please avoid using the **origFunc parameter. In some cases (not always)
    it may chop off important parts of the code (ex. LEAs for printf()s/puts()es).
    The instructions are actually executed in the backup prologue, but they are lost
    while jumping back to the original implementation.
    This is due to the long size of the shellcode, which forces a very large backup.

    I am thinking of a workaround, but for now just use the __restore() function.
    Or if it works in your case, no other known problems w/ **origFunc.

  */

#ifdef ERR_ARCH_NOT_SUPPORTED
  fprintf(stderr, "[!] Error: Architecture i386 is not currently supported. Please use harpoon for x86.\n");
  exit(0);
#endif

  assert(function);
  assert(replacement);

  /* this should be replaced asap, as it fucks one register */
  char jmp64[] = {
    '\x48', '\xb8', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF',
    '\xff', '\xe0'
  };

  long *originalFunctionPtr = (long *)function;

  int eatenCount = 0;
  int originalInstructionCount = 0;
  char originalInstructions[kOriginalInstructionsSize];
  uint8_t originalInstructionSizes[kOriginalInstructionsSize];
  uint64_t jumpRelativeInstruction = 0;

  /* shoutout to rentzsch! */
  Boolean canBeOverridden = eatKnownInstructions((unsigned char *)originalFunctionPtr, &jumpRelativeInstruction, &eatenCount, originalInstructions, &originalInstructionCount, originalInstructionSizes);

  if(canBeOverridden) {
    vm_protect(mach_task_self(), (vm_address_t)function, 32, 0, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE);
    vm_protect(mach_task_self(), (vm_address_t)replacement, 32, 0, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE);

    eaten = eatenCount;

    if(origFunc) {
      unsigned char *prologue = (unsigned char*)malloc(64);
      vm_protect(mach_task_self(), (vm_address_t)prologue, 64, 0, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE);

      memcpy(prologue, function, eatenCount);
      _craftJump(jmp64, sizeof(jmp64), function+eatenCount);
      memcpy(prologue+eatenCount, jmp64, sizeof(jmp64));

      *origFunc = prologue;
    }

    if(restorePtr)
      memcpy(restorePtr, function, eatenCount);

    _craftJump(jmp64, sizeof(jmp64), replacement);
    memcpy(function, (const void*)jmp64, sizeof(jmp64)); // throws hook @ original function

    size_t nop_sz = (eatenCount-sizeof(jmp64));
    memset(function+sizeof(jmp64), '\x90', nop_sz);

    return 0;
  } else {
    fprintf(stderr, "[!] Function at %p cannot be overridden!\n", function);
    return -1;
  }

}

/* stolen from mach_override, will probably be rewritten w/ capstone – thx again rentzsch */
Boolean eatKnownInstructions(unsigned char *code, uint64_t *newInstruction, int *howManyEaten, char *originalInstructions,
    int *originalInstructionCount, uint8_t *originalInstructionSizes )
{
    Boolean allInstructionsKnown = true;
    int totalEaten = 0;
    int remainsToEat = 12; // a JMP instruction takes 5 bytes
    int instructionIndex = 0;
    ud_t ud_obj;

    if (howManyEaten) *howManyEaten = 0;
    if (originalInstructionCount) *originalInstructionCount = 0;
    ud_init(&ud_obj);
    ud_set_mode(&ud_obj, 64);
    ud_set_input_buffer(&ud_obj, code, 64); // Assume that 'code' points to at least 64bytes of data.
    while (remainsToEat > 0) {
        if (!ud_disassemble(&ud_obj)) {
            allInstructionsKnown = false;
            fprintf(stderr, "mach_override: some instructions unknown! Need to update libudis86\n");
            break;
        }

        // At this point, we've matched curInstr
        int eaten = ud_insn_len(&ud_obj);
        remainsToEat -= eaten;
        totalEaten += eaten;

        if (originalInstructionSizes) originalInstructionSizes[instructionIndex] = eaten;
        instructionIndex += 1;
        if (originalInstructionCount) *originalInstructionCount = instructionIndex;
    }


    if (howManyEaten) *howManyEaten = totalEaten;

    if (originalInstructions) {
        Boolean enoughSpaceForOriginalInstructions = (totalEaten < kOriginalInstructionsSize);

        if (enoughSpaceForOriginalInstructions) {
            memset(originalInstructions, 0x90 /* NOP */, kOriginalInstructionsSize); // fill instructions with NOP
            bcopy(code, originalInstructions, totalEaten);
        } else {
            // printf ("Not enough space in island to store original instructions. Adapt the island definition and kOriginalInstructionsSize\n");
            return false;
        }
    }

    if (allInstructionsKnown) {
        // save last 3 bytes of first 64bits of codre we'll replace
        uint64_t currentFirst64BitsOfCode = *((uint64_t *)code);
        currentFirst64BitsOfCode = OSSwapInt64(currentFirst64BitsOfCode); // back to memory representation
        currentFirst64BitsOfCode &= 0x0000000000FFFFFFLL;

        // keep only last 3 instructions bytes, first 5 will be replaced by JMP instr
        *newInstruction &= 0xFFFFFFFFFF000000LL; // clear last 3 bytes
        *newInstruction |= (currentFirst64BitsOfCode & 0x0000000000FFFFFFLL); // set last 3 bytes
    }

    return allInstructionsKnown;
}
