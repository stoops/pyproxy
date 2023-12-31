/*
gcc -o z z.c
./z | tr -d '[]' | awk '{ print $NF }' | sort | uniq -c | sort -n
*/

#include <stdio.h>
#include "c.c"

int main()
{
	unsigned char t, s[256];
	unsigned int o, l = 8, w = 2;
	for (int i = 0; i < l; ++i) {
		for (int j = 0; j < l; ++j) {
			for (int k = 0; k < l; ++k) {
				for (int y = 0, z = 0; y < 1; y += 0) {
					if (y < 1) { /* no-op */ } else { break; }
					for (int x = 0; x < 256; ++x) { s[x] = x; }
					t = s[y]; s[y] = s[z]; s[z] = t;
					sums(&o, s, i, j, k);
					printf("debug [%d][%d][%d]-[%d][%d] == [%u]\n",i,j,k,y,z,o);
					z = ((z + 1) % w); if (z == 0) { y += 1; }
				}
			}
		}
	}
	return 0;
}
