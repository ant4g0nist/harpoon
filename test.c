#include "harpoon64.h"
#include <stdio.h>
#include <CoreServices/CoreServices.h>

#define kOriginalInstructionsSize 32

unsigned char *ctx;

void a()
{

	int x = 5;

	puts("\noriginal function here!");
	while(x>0){
		printf("%d\n",x);
		--x;
	}

}

void b(int x)
{

	printf("[+] replacement_func: hook succeedeed!\n");
	__restore(a, ctx);
	a();

}

int main(void)
{

	ctx = (unsigned char*)malloc(32);
	__throw_hook(a, b, NULL, ctx);
	a();

	return 0;
}
