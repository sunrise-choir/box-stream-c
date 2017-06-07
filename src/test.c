#include "box-stream.h"

#include <assert.h>
#include <stdio.h>
#include <sodium.h>

int main()
{
  assert(sodium_init() != -1);

  printf("%s\n", "foo");
}
