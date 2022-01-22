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
#include <thread>
#include <vector>

#include "client.h"

void subscribe(LightningClient* client, uint64_t object_id) {
  client->Subscribe(object_id);
}

int main(int argc, char **argv) {
  LightningClient client("/tmp/lightning", "password");
  std::vector<std::thread> threads;
  threads.reserve(100);

  for (uint64_t object_id = 0; object_id < 100; object_id ++) {
    threads.emplace_back(subscribe, &client, object_id);
  }

  for (auto& thread : threads) {
    thread.join();
  }

  return 0;
}