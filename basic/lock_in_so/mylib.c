#include <stdio.h>

int global_var = 0;

void increment_global_var()
{
	global_var++;
}


void print_global_var()
{
	printf("global_var: address=%p, data=%d\n", &global_var, global_var);
}