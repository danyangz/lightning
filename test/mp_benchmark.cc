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
#include <vector>

#include "client.h"

void test(LightningClient &client, int object_size, int num_tests, int test_id, const std::vector<uint64_t> &object_ids) {
  char *a = new char[object_size];
  for (int i = 0; i < object_size; i++) {
    a[i] = 'a';
  }

  std::cout << object_size << ", ";

  auto start = std::chrono::high_resolution_clock::now();

  for (uint64_t i = 0; i < num_tests; i++) {
    uint8_t *ptr;
    int status = client.Create(object_ids[i], &ptr, object_size);
    memcpy(ptr, a, object_size);
    status = client.Seal(object_ids[i]);
    char *out;
    size_t size;
    status = client.Get(object_ids[i], (uint8_t **)&out, &size);
    status = client.Delete(object_ids[i]);

  }

  auto end = std::chrono::high_resolution_clock::now();

  std::chrono::duration<double> duration = end - start;

  double time = duration.count();

  std::cout << num_tests/time << std::endl;

  delete[] a;
}

int main(int argc, char **argv) {
  LightningClient client("/tmp/lightning", "password");

  int test_id = atoi(argv[1]);

  srand(getpid());
  
  std::vector<uint64_t> object_ids;
  int num_tests = 10000;
  object_ids.reserve(num_tests);
  for (int i=0;i<num_tests;i++) {
    object_ids[i] = test_id * num_tests + i;
  }

  while (true) {
    test(client, 1024, num_tests, test_id, object_ids);
  }

  return 0;
}
