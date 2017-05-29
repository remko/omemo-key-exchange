#include <stdio.h>

// For debugging
void print_bytes(unsigned char* key, int n) {
	for(int i =0; i < n; ++i) {
		printf("%02x", key[i]);
	}
}


