/*
gcc -o z z.c
./z | tr -d '[]' | awk '{ print $NF }' | sort | uniq -c | sort -n
*/

#include <stdio.h>
#include "c.c"

int main()
{
	unsigned char a, b, c;
	unsigned char s[256], o[16], i[8];
	unsigned char *t = "msg", *v = "rnd", *u = "key";
	int l = 10;
	for (int x = 0; x < l; ++x) {
		for (int y = 0; y < l; ++y) {
			for (int z = 0; z < l; ++z) {
				a = 0; b = 0; c = 0;
				i[0] = x; i[1] = y; i[2] = z;
				keys(s, 384, v, 3, u, 3);
				ciph(o, i, 3, &a, &b, &c, s, 'e');
				sums(o, 8, a, b, c, s);
				printf("out [%d][%d][%d] == [%02x%02x%02x%02x%02x%02x%02x%02x]\n",x,y,z,o[0],o[1],o[2],o[3],o[4],o[5],o[6],o[7]);
			}
		}
	}
	return 0;
}
