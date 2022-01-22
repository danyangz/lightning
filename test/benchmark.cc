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

void test(LightningClient &client, int object_size) {
  char *a = new char[object_size];
  for (int i = 0; i < object_size; i++) {
    a[i] = 'a';
  }

  uint64_t num_tests = 100;

  std::cout << object_size << ", ";

  auto start = std::chrono::high_resolution_clock::now();

  for (uint64_t i = 0; i < num_tests; i++) {
    uint8_t *ptr;
    int status = client.Create(i, &ptr, object_size);
    memcpy(ptr, a, object_size);
    status = client.Seal(i);
  }

  auto end = std::chrono::high_resolution_clock::now();

  std::chrono::duration<double> duration = end - start;

  std::cout << duration.count() / num_tests << ", ";

  char *out;
  size_t size;

  start = std::chrono::high_resolution_clock::now();
  for (uint64_t i = 0; i < num_tests; i++) {
    int status = client.Get(i, (uint8_t **)&out, &size);
  }

  end = std::chrono::high_resolution_clock::now();

  duration = end - start;

  std::cout << duration.count() / num_tests << ", ";

  start = std::chrono::high_resolution_clock::now();
  for (uint64_t i = 0; i < num_tests; i++) {
    int status = client.Delete(i);
  }

  end = std::chrono::high_resolution_clock::now();

  duration = end - start;

  std::cout << duration.count() / num_tests << std::endl;

  delete[] a;
}

int main(int argc, char **argv) {
  LightningClient client("/tmp/lightning", "password");

  srand(getpid());

  int test_runs = 100;
  
  for (int i = 0; i < test_runs; i++) {
    int object_size = 16;
    while (object_size <= 1024 * 1024) {
      test(client, object_size);
      object_size *= 2;
    }
  }

  return 0;
}
