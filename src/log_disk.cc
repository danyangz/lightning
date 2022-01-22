#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log_disk.h"

UndoLogDisk::UndoLogDisk(size_t log_size, uint8_t *shm_base, size_t shm_size)
    : shm_base_(shm_base), shm_size_(shm_size) {
  pid_t pid = getpid();
  auto pid_str = "log-" + std::to_string(pid);
  log_fd_ = shm_open(pid_str.c_str(), O_CREAT | O_RDWR, 0666);
  int status = ftruncate(log_fd_, log_size);
  if (status < 0) {
    perror("cannot ftruncate");
    exit(-1);
  }

  log_base_ =
      (uint8_t *)mmap(nullptr, log_size, PROT_WRITE, MAP_SHARED, log_fd_, 0);
}

void UndoLogDisk::BeginTx() {
  *(uint64_t *)log_base_ = 0;
  std::atomic_thread_fence(std::memory_order_acquire);
}

void UndoLogDisk::CommitTx() {
  std::atomic_thread_fence(std::memory_order_release);
  *(uint64_t *)log_base_ = 0;
}

void UndoLogDisk::Write(sm_offset offset, uint64_t value) {
  assert(offset % 8 == 0);
  uint64_t num_entry = *(uint64_t *)log_base_;
  LogEntry *entry = (LogEntry *)(log_base_ + sizeof(uint64_t));
  entry[num_entry].offset = offset;
  entry[num_entry].value = *(uint64_t *)&shm_base_[offset];
  *(uint64_t *)log_base_ = num_entry + 1;
  std::atomic_thread_fence(std::memory_order_seq_cst);
  *(uint64_t *)&shm_base_[offset] = value;
}
