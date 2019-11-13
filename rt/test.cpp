/*
 * gcc -ggdb -o test test.c
 */
#include <stdio.h>

class A
{
    public:
        A() { printf("%s\n", __FUNCTION__); }
        ~A() {}
};

void __attribute__((constructor)) a_constructor()
{
    printf("%s\n", __FUNCTION__);
}

static A a;

int main()
{
	printf("%s\n", __FUNCTION__);
}
