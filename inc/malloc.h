#ifndef MALLOC_H
#define MALLOC_H

#include "log_disk.h"
#include "memory.h"

class MemAllocator {
public:
  MemAllocator(LightningStoreHeader *header, UndoLogDisk *disk);
  void Init(sm_offset start, size_t size);

  sm_offset MallocShared(size_t size);
  void FreeShared(sm_offset offset);

  void PrintAvalaibleMemory();

  // for crash recovery
  void FreeSharedNoLog(sm_offset offset);

private:
  void split_memory_to_free_lists(sm_offset offset, size_t size);
  int64_t create_block(sm_offset ptr, size_t size);
  void add_to_free_list(int index, int64_t mem_entry_index);
  int64_t create_block_nolog(sm_offset ptr, size_t size);
  void add_to_free_list_nolog(int index, int64_t mem_entry_index);
  int64_t remove_from_free_list(int index);
  int64_t get_free_block(int index);
  void remove_block(int index, int64_t mem_entry_index);
  void remove_block_nolog(int index, int64_t mem_entry_index);
  int64_t separate_buddy(int64_t mem_index, int index);
  int64_t merge_blocks(int64_t mem_entry_index1, int64_t mem_entry_index2,
                       int index);
  int64_t merge_blocks_nolog(int64_t mem_entry_index1, int64_t mem_entry_index2,
                             int index);

  int64_t allocate_memory_entry();
  int64_t allocate_memory_entry_nolog();
  void deallocate_memory_entry(int64_t mem_entry_index);
  void deallocate_memory_entry_nolog(int64_t mem_entry_index);

  LightningStoreHeader *header_;
  FreeList *free_list_;
  uint8_t *base_;
  UndoLogDisk *disk_;
};

#endif // MALLOC_H
