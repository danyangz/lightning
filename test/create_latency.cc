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
#include <cmath>

#include "client.h"

int main() {
  LightningClient client("/tmp/lightning", "password");

  char a[16];
  for (int i = 0; i < 16; i++)
    a[i] = 'a';

  uint64_t num_tests = 100;

  auto start = std::chrono::high_resolution_clock::now();

  for (uint64_t i = 0; i < num_tests; i++) {
    uint8_t *ptr;
    int status = client.Create(i, &ptr, 16);
    memcpy(ptr, a, 16);
    status = client.Seal(i);
  }

  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end - start;

  std::cout << duration.count()/num_tests << std::endl;

  return 0;
}