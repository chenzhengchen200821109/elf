#include <stdio.h>
#include "libdummy.h"

int main()
{
    int a, b;
    int res = 0;

    printf("Enter the first number: ");
    scanf("%d", &a);
    printf("Enter the second number: ");
    scanf("%d", &b);
    res = dummy_add(a, b);
    printf("Result is: %d\n", res);

    return 0;
}
