/* gcc --static init.c -o sbin/init */

#include <stdint.h>
#include <unistd.h>

uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);

void
bfdebug(const char *str)
{
	int i = 0;
	while(str[i] != 0) {
		_vmcall(42, 0, str[i], 0);
		i++;
	}
}

int main(int argc, char *argv[])
{
	while(1) {
    	bfdebug("Hello World\n");
		sleep(1);
	}

	return 0;
}
