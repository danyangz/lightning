#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "object_log.h"

ObjectLog::ObjectLog(uint8_t *object_log_base, sm_offset object_log_offset,
                     UndoLogDisk *disk)
    : object_log_base_(object_log_base), object_log_offset_(object_log_offset),
      disk_(disk) {
  LogObjectEntry *objects = (LogObjectEntry *)&object_log_base_[0];
  for (int i = 0; i < OBJECT_LOG_SIZE; i++) {
    objects[i].in_use = false;
  }
}

int64_t ObjectLog::find_object(int64_t object_id) {
  auto search = object_cache_.find(object_id);
  if (search == object_cache_.end()) {
    return -1;
  }
  return object_cache_[object_id];
}

void ObjectLog::erase_object(int64_t object_id) {
  auto search = object_cache_.find(object_id);
  if (search == object_cache_.end()) {
    return;
  }
  object_cache_.erase(search);
}

void ObjectLog::insert_object(int64_t object_id, int64_t index) {
  object_cache_[object_id] = index;
}

int64_t ObjectLog::find_new_entry(int64_t object_id) {
  LogObjectEntry *objects = (LogObjectEntry *)&object_log_base_[0];
  int index = object_id % OBJECT_LOG_SIZE;
  if (index < 0) {
    index += OBJECT_LOG_SIZE;
  }
  while (true) {
    if (!objects[index].in_use) {
      return index;
    }
    index++;
    if (index >= OBJECT_LOG_SIZE)
      index -= OBJECT_LOG_SIZE;
  }
}

void ObjectLog::OpenObject(int64_t object_id) {
  if (find_object(object_id) >= 0) {
    return;
  }

  int64_t index = find_new_entry(object_id);

  assert(index >= 0);
  assert(index < OBJECT_LOG_SIZE);
  disk_->Write(object_log_offset_ + index * sizeof(LogObjectEntry), object_id);
  disk_->Write(object_log_offset_ + index * sizeof(LogObjectEntry) + 8, true);

  insert_object(object_id, index);
}

void ObjectLog::CloseObject(int64_t object_id) {
  int64_t index = find_object(object_id);
  if (index < 0) {
    return;
  }

  assert(index >= 0);
  assert(index < OBJECT_LOG_SIZE);

  disk_->Write(object_log_offset_ + index * sizeof(LogObjectEntry) + 8, false);
  erase_object(object_id);
}