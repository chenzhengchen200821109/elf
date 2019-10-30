//compile: gcc -o bss bss.c

#include <stdio.h>
#include <stdlib.h>

int data[2] = { 0 };
int bss[2];

int main()
{
    for (int i = 0; i < 2; i++)
        bss[i] = i;
    printf("the bss[1] = %d\n", bss[1]);

    return 0;
}
