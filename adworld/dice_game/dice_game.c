#include <stdio.h>
#include <stdlib.h>

int main() {
  srand(0);
  for (int i = 0; i < 50; i++) {
    int a = rand();
    printf("%d\n", a + (a / 6) * (-6) + 1);
  }
}
