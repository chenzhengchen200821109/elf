#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#define SLEEP 3

char test_str[] = "[+] test";
static int counter = 0;

int main()
{
    while(1) 
    {
        printf("%s[%d]\n", test_str, counter);
        sleep(SLEEP); //等待attach
        counter++;
    }
}
