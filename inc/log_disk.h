#ifndef UNDO_DISK_H
#define UNDO_DISK_H

#include <sys/types.h>

#include "memory.h"

struct LogEntry {
  sm_offset offset;
  int64_t value;
};

class UndoLogDisk {
public:
  UndoLogDisk(size_t log_size, uint8_t *shm_base, size_t shm_size);

  void BeginTx();
  void CommitTx();

  void Write(sm_offset offset, uint64_t value);

protected:
  int log_fd_;

  uint8_t *shm_base_;
  size_t shm_size_;
  uint8_t *log_base_;
  size_t log_size_;
};

#define LOGGED_WRITE(lval, rval, hdr_ptr, log_ptr)                             \
  do {                                                                         \
    sm_offset offset = (uint8_t *)(&(lval)) - (uint8_t *)(hdr_ptr);            \
    log_ptr->Write(offset, rval);                                              \
  } while (false)

#endif // UNDO_DISK_H
