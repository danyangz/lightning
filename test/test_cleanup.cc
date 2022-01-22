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
#include <cassert>
#include <sys/wait.h>

#include "client.h"

int main(int argc, char **argv) {
  int object_size = 100;
  char a[100];
  pid_t child_pid = fork();
  if (child_pid == 0) {
    LightningClient client("/tmp/lightning", "password");
    uint8_t *ptr;
    int status = client.Create(123, &ptr, object_size);
    assert(status == 0);
    memcpy(ptr, a, object_size);
    status = client.Seal(123);
    assert(status == 0);
  } else {
    sleep(2);
    LightningClient client("/tmp/lightning", "password");
    int status;
    pid_t pid = wait(&status);
    assert (pid == child_pid);
    assert (status == 0);
    sleep(2);
    char *out;
    size_t size;
    status = client.Get(123, (uint8_t **)&out, &size);
    assert (status == -1);
  }

  return 0;
}