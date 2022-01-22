#include <assert.h>
#include <iostream>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "malloc.h"

MemAllocator::MemAllocator(LightningStoreHeader *header, UndoLogDisk *disk)
    : header_(header), disk_(disk) {
  base_ = (uint8_t *)header;
  free_list_ = &header->free_list;
}

static __always_inline int fls(unsigned long x) {
  int r = 64;
  if (!x)
    return 0;
  if (!(x & 0xffffffff00000000u)) {
    x <<= 32;
    r -= 32;
  }
  if (!(x & 0xffff000000000000u)) {
    x <<= 16;
    r -= 16;
  }
  if (!(x & 0xff00000000000000u)) {
    x <<= 8;
    r -= 8;
  }
  if (!(x & 0xf000000000000000u)) {
    x <<= 4;
    r -= 4;
  }
  if (!(x & 0xc000000000000000u)) {
    x <<= 2;
    r -= 2;
  }
  if (!(x & 0x8000000000000000u)) {
    x <<= 1;
    r -= 1;
  }
  return r;
}

int64_t MemAllocator::create_block(sm_offset start, size_t size) {
  int64_t mem_entry_index = allocate_memory_entry();
  MemoryEntry *entry = &header_->memory_entries[mem_entry_index];
  MemoryHeader *head = (MemoryHeader *)&base_[start];

  LOGGED_WRITE(head->index, mem_entry_index, header_, disk_);
  // head->index = mem_entry_index;

  LOGGED_WRITE(entry->in_use, false, header_, disk_);
  // entry->in_use = false;

  LOGGED_WRITE(entry->offset, start, header_, disk_);
  // entry->offset = start;

  LOGGED_WRITE(entry->size, size, header_, disk_);
  // entry->size = size;

  LOGGED_WRITE(entry->prev, -1, header_, disk_);
  // entry->prev = -1;

  LOGGED_WRITE(entry->next, -1, header_, disk_);
  // entry->next = -1;

  for (int i = 0; i < 32; i++) {
    LOGGED_WRITE(entry->buddy[i], -1, header_, disk_);
    // entry->buddy[i] = -1;
  }

  return mem_entry_index;
}

void MemAllocator::add_to_free_list(int index, int64_t mem_entry_index) {
  assert(index >= MINIMAL_BLOCK_SIZE_LOG);
  assert(index <= MAXIMUM_BLOCK_SIZE_LOG);

  MemoryEntry *entry = &header_->memory_entries[mem_entry_index];

  assert(!entry->in_use);
  assert(1 << index == entry->size);

  if (free_list_->free_list_head[index] > 0) {
    int64_t head_index = free_list_->free_list_head[index];
    MemoryEntry *head = &header_->memory_entries[head_index];
    LOGGED_WRITE(head->prev, mem_entry_index, header_, disk_);
    // head->prev = mem_entry_index;

    LOGGED_WRITE(entry->next, head_index, header_, disk_);
    // entry->next = head_index;
  }

  LOGGED_WRITE(free_list_->free_list_head[index], mem_entry_index, header_,
               disk_);
  // free_list_->free_list_head[index] = mem_entry_index;
}

int64_t MemAllocator::allocate_memory_entry() {
  int64_t i = header_->memory_entry_free_list;
  assert(i >= 0);

  LOGGED_WRITE(header_->memory_entry_free_list,
               header_->memory_entries[i].free_list_next, header_, disk_);
  // header_->memory_entry_free_list =
  // header_->memory_entries[i].free_list_next;

  LOGGED_WRITE(header_->memory_entries[i].free_list_next, -1, header_, disk_);
  // header_->memory_entries[i].free_list_next = -1;
  return i;
}

int64_t MemAllocator::allocate_memory_entry_nolog() {
  int64_t i = header_->memory_entry_free_list;
  assert(i >= 0);

  header_->memory_entry_free_list = header_->memory_entries[i].free_list_next;
  header_->memory_entries[i].free_list_next = -1;
  return i;
}

void MemAllocator::deallocate_memory_entry(int64_t i) {
  assert(header_->memory_entries[i].free_list_next == -1);
  int64_t j = header_->memory_entry_free_list;
  LOGGED_WRITE(header_->memory_entries[i].free_list_next, j, header_, disk_);
  // header_->memory_entries[i].free_list_next = j;
  LOGGED_WRITE(header_->memory_entry_free_list, i, header_, disk_);
  // header_->memory_entry_free_list = i;
}

void MemAllocator::deallocate_memory_entry_nolog(int64_t i) {
  assert(header_->memory_entries[i].free_list_next == -1);
  int64_t j = header_->memory_entry_free_list;
  header_->memory_entries[i].free_list_next = j;
  header_->memory_entry_free_list = i;
}

int64_t MemAllocator::create_block_nolog(sm_offset start, size_t size) {
  int64_t mem_entry_index = allocate_memory_entry_nolog();
  MemoryEntry *entry = &header_->memory_entries[mem_entry_index];
  MemoryHeader *head = (MemoryHeader *)&base_[start];
  head->index = mem_entry_index;

  entry->in_use = false;
  entry->offset = start;
  entry->size = size;
  entry->prev = -1;
  entry->next = -1;
  for (int i = 0; i < 32; i++) {
    entry->buddy[i] = -1;
  }

  return mem_entry_index;
}

void MemAllocator::add_to_free_list_nolog(int index, int64_t mem_entry_index) {
  assert(index >= MINIMAL_BLOCK_SIZE_LOG);
  assert(index <= MAXIMUM_BLOCK_SIZE_LOG);

  MemoryEntry *entry = &header_->memory_entries[mem_entry_index];

  assert(!entry->in_use);
  assert(1 << index == entry->size);

  if (free_list_->free_list_head[index] > 0) {
    int64_t head_index = free_list_->free_list_head[index];
    MemoryEntry *head = &header_->memory_entries[head_index];
    head->prev = mem_entry_index;
    entry->next = head_index;
  }

  free_list_->free_list_head[index] = mem_entry_index;
}

void MemAllocator::split_memory_to_free_lists(sm_offset offset, size_t size) {
  sm_offset cur_offset = offset;
  size_t cur_size = size;
  while (true) {
    int size_index = MINIMAL_BLOCK_SIZE_LOG;
    size_t block_size = 1 << size_index;

    if (cur_size < block_size) {
      return;
    }

    while (cur_size > block_size * 2) {
      size_index++;
      block_size *= 2;
    }

    int64_t cur_index = create_block_nolog(cur_offset, block_size);
    add_to_free_list_nolog(size_index, cur_index);

    cur_offset += block_size;
    cur_size -= block_size;
  }
}

void MemAllocator::Init(sm_offset offset, size_t size) {
  // initialize free lists
  for (int i = 0; i <= 32; i++) {
    free_list_->free_list_head[i] = -1;
  }

  split_memory_to_free_lists(offset, size);
}

int64_t MemAllocator::remove_from_free_list(int index) {
  assert(index >= MINIMAL_BLOCK_SIZE_LOG);
  assert(index <= MAXIMUM_BLOCK_SIZE_LOG);

  // test if the free list is vacant
  assert(free_list_->free_list_head[index] >= 0);

  int64_t head_index = free_list_->free_list_head[index];
  MemoryEntry *head = &header_->memory_entries[head_index];
  LOGGED_WRITE(free_list_->free_list_head[index], head->next, header_, disk_);
  // free_list_->free_list_head[index] = head->next;

  if (free_list_->free_list_head[index] >= 0) {
    int64_t new_head_index = free_list_->free_list_head[index];
    MemoryEntry *new_head = &header_->memory_entries[new_head_index];
    LOGGED_WRITE(new_head->prev, -1, header_, disk_);
    // new_head->prev = -1;
  }
  LOGGED_WRITE(head->next, -1, header_, disk_);
  // head->next = -1;

  // if the removed block is already in use, there is a huge problem
  assert(!head->in_use);
  return head_index;
}

int64_t MemAllocator::separate_buddy(int64_t mem_index, int index) {
  MemoryEntry *entry = &header_->memory_entries[mem_index];
  size_t block_size = (entry->size) >> 1;

  assert(!entry->in_use);

  sm_offset smaller_block_offset = entry->offset + block_size;
  int64_t smaller_index = create_block(smaller_block_offset, block_size);

  assert(smaller_index != mem_index);

  LOGGED_WRITE(entry->buddy[index], smaller_index, header_, disk_);
  // entry->buddy[index] = smaller_index;

  MemoryEntry *smaller_entry = &header_->memory_entries[smaller_index];

  LOGGED_WRITE(smaller_entry->buddy[index], mem_index, header_, disk_);
  // smaller_entry->buddy[index] = mem_index;

  LOGGED_WRITE(entry->size, block_size, header_, disk_);
  // entry->size = block_size;

  return smaller_index;
}

int64_t MemAllocator::get_free_block(int size_index) {
  if (free_list_->free_list_head[size_index] >= 0) {
    return remove_from_free_list(size_index);
  }

  // find a block that is larger than the request block
  int i = size_index + 1;
  while (free_list_->free_list_head[i] < 0) {
    assert(i <= MAXIMUM_BLOCK_SIZE_LOG);
    i++;
  }

  int64_t mem_entry_index = remove_from_free_list(i);

  // need to break the block (i - index) times
  for (int j = i - 1; j >= size_index; j--) {
    int64_t smaller_block_index = separate_buddy(mem_entry_index, j);
    add_to_free_list(j, smaller_block_index);
  }

  return mem_entry_index;
}

sm_offset MemAllocator::MallocShared(size_t size) {
  size_t real_size = size + sizeof(MemoryEntry);

  int size_index = fls(real_size - 1);
  if (size_index < MINIMAL_BLOCK_SIZE_LOG) {
    size_index = MINIMAL_BLOCK_SIZE_LOG;
  }

  int64_t mem_index = get_free_block(size_index);
  assert(mem_index >= 0);

  MemoryEntry *entry = &header_->memory_entries[mem_index];
  LOGGED_WRITE(entry->in_use, true, header_, disk_);
  // entry->in_use = true;

  return entry->offset + sizeof(MemoryHeader);
}

void MemAllocator::remove_block(int index, int64_t mem_entry_index) {
  assert(index >= MINIMAL_BLOCK_SIZE_LOG);
  assert(index <= MAXIMUM_BLOCK_SIZE_LOG);

  assert(free_list_->free_list_head[index] >= 0);

  int64_t head_index = free_list_->free_list_head[index];
  MemoryEntry *head = &header_->memory_entries[head_index];
  MemoryEntry *block = &header_->memory_entries[mem_entry_index];
  if (head_index == mem_entry_index) {
    LOGGED_WRITE(free_list_->free_list_head[index], head->next, header_, disk_);
    // free_list_->free_list_head[index] = head->next;
    if (free_list_->free_list_head[index] >= 0) {
      int64_t new_head_index = free_list_->free_list_head[index];
      MemoryEntry *new_head = &header_->memory_entries[new_head_index];
      LOGGED_WRITE(new_head->prev, -1, header_, disk_);
      // new_head->prev = -1;
    }
    LOGGED_WRITE(head->next, -1, header_, disk_);
    // head->next = -1;
  } else {
    int64_t cur_index = head_index;
    MemoryEntry *cur = head;
    while (cur->next >= 0) {
      if (cur->next == mem_entry_index) {
        LOGGED_WRITE(cur->next, block->next, header_, disk_);
        // cur->next = block->next;
        if (block->next >= 0) {
          MemoryEntry *next_block = &header_->memory_entries[cur->next];
          LOGGED_WRITE(next_block->prev, cur_index, header_, disk_);
          // next_block->prev = cur_index;
        }
        LOGGED_WRITE(block->next, -1, header_, disk_);
        // block->next = -1;

        LOGGED_WRITE(block->prev, -1, header_, disk_);
        // block->prev = -1;
        return;
      }
      cur_index = cur->next;
      cur = &header_->memory_entries[cur_index];
    }
    assert(false);
  }
}

void MemAllocator::remove_block_nolog(int index, int64_t mem_entry_index) {
  assert(index >= MINIMAL_BLOCK_SIZE_LOG);
  assert(index <= MAXIMUM_BLOCK_SIZE_LOG);

  assert(free_list_->free_list_head[index] >= 0);

  int64_t head_index = free_list_->free_list_head[index];
  MemoryEntry *head = &header_->memory_entries[head_index];
  MemoryEntry *block = &header_->memory_entries[mem_entry_index];
  if (head_index == mem_entry_index) {
    free_list_->free_list_head[index] = head->next;
    if (free_list_->free_list_head[index] >= 0) {
      int64_t new_head_index = free_list_->free_list_head[index];
      MemoryEntry *new_head = &header_->memory_entries[new_head_index];
      new_head->prev = -1;
    }
    head->next = -1;
  } else {
    int64_t cur_index = head_index;
    MemoryEntry *cur = head;
    while (cur->next >= 0) {
      if (cur->next == mem_entry_index) {
        cur->next = block->next;
        if (block->next >= 0) {
          MemoryEntry *next_block = &header_->memory_entries[cur->next];
          next_block->prev = cur_index;
        }
        block->next = -1;
        block->prev = -1;
        return;
      }
      cur_index = cur->next;
      cur = &header_->memory_entries[cur_index];
    }
    assert(false);
  }
}

int64_t MemAllocator::merge_blocks(int64_t block1_entry_index,
                                   int64_t block2_entry_index, int index) {

  MemoryEntry *block1 = &header_->memory_entries[block1_entry_index];
  MemoryEntry *block2 = &header_->memory_entries[block2_entry_index];

  assert(block1->buddy[index] == block2_entry_index);
  assert(block2->buddy[index] == block1_entry_index);

  remove_block(index, block2_entry_index);

  int64_t first, second;
  if (block1->offset < block2->offset) {
    first = block1_entry_index;
    second = block2_entry_index;
  } else {
    first = block2_entry_index;
    second = block1_entry_index;
  }

  MemoryEntry *first_block = &header_->memory_entries[first];
  MemoryEntry *second_block = &header_->memory_entries[second];

  LOGGED_WRITE(first_block->buddy[index], -1, header_, disk_);
  // first_block->buddy[index] = -1;

  LOGGED_WRITE(second_block->buddy[index], -1, header_, disk_);
  // second_block->buddy[index] = -1;

  LOGGED_WRITE(first_block->size, first_block->size + second_block->size,
               header_, disk_);
  // first_block->size = first_block->size + second_block->size;

  MemoryHeader *header = (MemoryHeader *)&base_[first_block->offset];

  LOGGED_WRITE(header->index, first, header_, disk_);
  // header->index = first;

  deallocate_memory_entry(second);

  return first;
}

int64_t MemAllocator::merge_blocks_nolog(int64_t block1_entry_index,
                                         int64_t block2_entry_index,
                                         int index) {

  MemoryEntry *block1 = &header_->memory_entries[block1_entry_index];
  MemoryEntry *block2 = &header_->memory_entries[block2_entry_index];

  assert(block1->buddy[index] == block2_entry_index);
  assert(block2->buddy[index] == block1_entry_index);

  remove_block_nolog(index, block2_entry_index);

  int64_t first, second;
  if (block1->offset < block2->offset) {
    first = block1_entry_index;
    second = block2_entry_index;
  } else {
    first = block2_entry_index;
    second = block1_entry_index;
  }

  MemoryEntry *first_block = &header_->memory_entries[first];
  MemoryEntry *second_block = &header_->memory_entries[second];

  first_block->buddy[index] = -1;
  second_block->buddy[index] = -1;
  first_block->size = first_block->size + second_block->size;

  MemoryHeader *header = (MemoryHeader *)&base_[first_block->offset];
  header->index = first;
  deallocate_memory_entry_nolog(second);

  return first;
}

int fls_uninlined(size_t size) { return fls(size); }

void MemAllocator::FreeShared(sm_offset offset) {
  sm_offset block_offset = offset - sizeof(MemoryHeader);
  MemoryHeader *header = (MemoryHeader *)&base_[block_offset];

  int64_t mem_entry_index = header->index;
  MemoryEntry *entry = &header_->memory_entries[mem_entry_index];
  /*
  if (entry->offset != block_offset) {
    std::cout << entry->offset << " != " << block_offset << std::endl;
  }
  */
  assert(entry->offset == block_offset);
  assert(entry->in_use);

  size_t size = entry->size;

  int index = fls_uninlined(size - 1);

  LOGGED_WRITE(entry->in_use, false, header_, disk_);
  // entry->in_use = false;

  for (int i = index; i < MAXIMUM_BLOCK_SIZE_LOG; i++) {
    int64_t buddy_mem_entry_index = entry->buddy[i];

    MemoryEntry *buddy_entry = &header_->memory_entries[buddy_mem_entry_index];

    if (buddy_mem_entry_index < 0 || buddy_entry->in_use ||
        buddy_entry->size != entry->size) {
      add_to_free_list(i, mem_entry_index);
      return;
    }
    assert(mem_entry_index != buddy_mem_entry_index);
    mem_entry_index = merge_blocks(mem_entry_index, buddy_mem_entry_index, i);
    entry = &header_->memory_entries[mem_entry_index];
  }

  add_to_free_list(MAXIMUM_BLOCK_SIZE_LOG, mem_entry_index);
}

void MemAllocator::PrintAvalaibleMemory() {
  for (int i = 0; i < 32; i++) {
    if (free_list_->free_list_head[i] > 0) {

      int64_t mem_entry_index = free_list_->free_list_head[i];
      std::cout << i << ":";

      while (mem_entry_index >= 0) {
        MemoryEntry *cur =
            (MemoryEntry *)&header_->memory_entries[mem_entry_index];
        std::cout << " " << mem_entry_index << ",";
        mem_entry_index = cur->next;
      }
      std::cout << std::endl;
    } else {
      std::cout << i << ":" << std::endl;
    }
  }
}

void MemAllocator::FreeSharedNoLog(sm_offset offset) {
  sm_offset block_offset = offset - sizeof(MemoryHeader);
  MemoryHeader *header = (MemoryHeader *)&base_[block_offset];

  int64_t mem_entry_index = header->index;
  MemoryEntry *entry = &header_->memory_entries[mem_entry_index];
  assert(entry->offset == block_offset);

  size_t size = entry->size;

  int index = fls_uninlined(size - 1);
  entry->in_use = false;

  for (int i = index; i < MAXIMUM_BLOCK_SIZE_LOG; i++) {
    int64_t buddy_mem_entry_index = entry->buddy[i];

    MemoryEntry *buddy_entry = &header_->memory_entries[buddy_mem_entry_index];

    if (buddy_mem_entry_index < 0 || buddy_entry->in_use ||
        buddy_entry->size != entry->size) {
      add_to_free_list_nolog(i, mem_entry_index);
      return;
    }

    assert(mem_entry_index != buddy_mem_entry_index);
    mem_entry_index =
        merge_blocks_nolog(mem_entry_index, buddy_mem_entry_index, i);
    entry = &header_->memory_entries[mem_entry_index];
  }

  add_to_free_list_nolog(MAXIMUM_BLOCK_SIZE_LOG, mem_entry_index);
}
