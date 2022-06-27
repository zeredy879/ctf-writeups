#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BYTE unsigned char

int main(int argc, char *argv[]) {

  unsigned int i;
  char v8[] = ":\"AL_RT^L*.?+6/46";
  char v7[] = "harambe";
  int v6 = 7;

  char s[18] = "";
  for (i = 0; i < strlen(v8); ++i) {
    s[i] = (char)(*((BYTE *)&v7 + i % v6) ^ v8[i]);
  }
  printf("%s\n", s);
  return 0;
}