//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <stdint.h>
#include <unistd.h>
#include <time.h>

extern "C" uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4) noexcept;

void
bfdebug(const char *str)
{
	int i = 0;
	while(str[i] != 0) {
		_vmcall(0xBF04000000000000, 1, 0x3f8, str[i]);
		i++;
	}
}

int main(int argc, char *argv[])
{
	time_t rawtime;

	while(1) {
		time(&rawtime);
		bfdebug("hello from init: ");
    	bfdebug(ctime(&rawtime));

		sleep(1);
	}

	return 0;
}
