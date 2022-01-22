#ifndef CLIENT_H
#define CLIENT_H
#include <string>
#include <vector>

#include "config.h"
#include "log_disk.h"
#include "malloc.h"
#include "object_log.h"

class LightningClient {
public:
  LightningClient(const std::string &store_socket, const std::string &password);

  int MultiPut(uint64_t object_id, std::vector<std::string> fields,
               std::vector<int64_t> subobject_sizes,
               std::vector<uint8_t *> subobjects);

  int MultiGet(uint64_t object_id, std::vector<std::string> in_fields,
               std::vector<int64_t> *out_field_sizes,
               std::vector<uint8_t *> *out_fields,
               std::vector<int64_t> *subobject_sizes,
               std::vector<uint8_t *> *subobjects);

  int MultiUpdate(uint64_t object_id, std::vector<std::string> fields,
                  std::vector<int64_t> subobject_sizes,
                  std::vector<uint8_t *> subobjects);

  int Create(uint64_t object_id, uint8_t **ptr, size_t size);

  int Seal(uint64_t object_id);

  int Get(uint64_t object_id, uint8_t **ptr, size_t *size);

  int Release(uint64_t object_id);

  int Delete(uint64_t object_id);

  int Subscribe(uint64_t object_id);

private:
  int store_conn_;
  int store_fd_;
  int log_fd_;

  LightningStoreHeader *header_;
  int size_;
  MemAllocator *allocator_;

  int64_t alloc_object_entry();
  void dealloc_object_entry(int64_t object_index);

  int64_t find_object(uint64_t object_id);
  int create_internal(uint64_t object_id, sm_offset *offset, size_t size);
  int get_internal(uint64_t object_id, sm_offset *ptr, size_t *size);
  int seal_internal(uint64_t object_id);
  int delete_internal(uint64_t object_id);
  int subscribe_internal(uint64_t object_id, sem_t **sem, bool *wait);
  void init_mpk();

  uint64_t object_id_from_str(const std::string &s);

  uint8_t *base_;

  int object_log_fd_;
  uint8_t *object_log_base_;
  ObjectLog *object_log_;
  pid_t pid_;

  UndoLogDisk *disk_;
};

#endif // CLIENT_H
