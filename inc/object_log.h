#ifndef LOG_H
#define LOG_H
#include <string>
#include <unordered_map>

#include "log_disk.h"
#include "memory.h"

#define OBJECT_LOG_SIZE 1048576

struct LogObjectEntry {
  uint64_t object_id;
  bool in_use;
};

class ObjectLog {
public:
  ObjectLog(uint8_t *object_log_base, sm_offset object_log_offset,
            UndoLogDisk *disk);

  void OpenObject(int64_t object_id);
  void CloseObject(int64_t object_id);

private:
  int object_log_fd_;

  sm_offset object_log_offset_;
  uint8_t *object_log_base_;

  UndoLogDisk *disk_;

  std::unordered_map<int64_t, int64_t> object_cache_;

  int64_t find_object(int64_t object_id);
  void erase_object(int64_t object_id);
  void insert_object(int64_t object_id, int64_t index);
  int64_t find_new_entry(int64_t object_id);
};

#endif // LOG_H
