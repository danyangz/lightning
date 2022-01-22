#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "client.h"

int main(int argc, char** argv) {
  int num_objects = atoi(argv[1]);

  LightningClient client("/tmp/lightning", "password");

  char a[1024];
  for (int i = 0; i < 1024; i++)
    a[i] = 'a';

  for (uint64_t i = 0; i < num_objects; i++) {
    uint8_t *ptr;
    int status = client.Create(i, &ptr, 1024);
    memcpy(ptr, a, 1024);
    status = client.Seal(i);
  }
  return 0;
}