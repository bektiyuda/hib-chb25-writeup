#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <err.h>


char buffer[180];
long target;
void setup(){
	setvbuf(stdin, buffer, _IONBF, 0);
	setvbuf(stdout, buffer, _IONBF, 0);
	setvbuf(stderr, buffer, _IONBF, 0);
}

void flag() {
  FILE *flagptr = fopen("flag.txt", "r");
  if (flagptr == NULL) {
    printf("Cannot find flag.txt!");
    exit(0);
  }
  char flag[100];
  fgets(flag, 100, flagptr);
  printf("FLAG: %s", flag);
  fclose(flagptr);
}

int main()
{
  setup();
  printf("\nWelcome to the challenge, I hope you enjoy playing this CTF and learn a lot about Cyber Security in the end.\n\nThe challenge is simple, overwrite the variable target and once the value is changed as intended, you will get the flag.\n\nYou can try playing around with the given binary first, then once you have the solver you can try doing it on the given netcat server.\n\nGHLF!!\n\n\n\n");
  target = 0;
  printf("Enter your input: ");
  fflush(stdout);
  gets(buffer);
  if(target == 0x4D734941) {
      printf("you have correctly got the variable to the right value\n");
      flag();
  } else {
      printf("Try again, you got 0x%08x\n", target);
  }
}
