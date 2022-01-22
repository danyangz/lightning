#include <assert.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <mutex>
#include <signal.h>
#include <stdlib.h>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <vector>

#include "client.h"

static int pkey_ = -1;
static std::mutex pkey_lock_;

#define LOCK                                                                   \
  while (!__sync_bool_compare_and_swap(&header_->lock_flag, 0, pid_)) {        \
    nanosleep((const struct timespec[]){{0, 0L}}, NULL);                       \
  }

#define UNLOCK                                                                 \
  std::atomic_thread_fence(std::memory_order_release);                         \
  header_->lock_flag = 0

int recv_fd(int unix_sock) {
  ssize_t size;
  struct msghdr msg;
  struct iovec iov;
  union {
    struct cmsghdr cmsghdr;
    char control[CMSG_SPACE(sizeof(int))];
  } cmsgu;
  struct cmsghdr *cmsg;
  char buf[2];
  int fd = -1;

  iov.iov_base = buf;
  iov.iov_len = 2;

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgu.control;
  msg.msg_controllen = sizeof(cmsgu.control);
  size = recvmsg(unix_sock, &msg, 0);
  if (size < 0) {
    std::cerr << "recvmsg error" << std::endl;
    return -1;
  }
  cmsg = CMSG_FIRSTHDR(&msg);
  if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
    if (cmsg->cmsg_level != SOL_SOCKET) {
      std::cerr << "invalid cmsg_level " << cmsg->cmsg_level << std::endl;
      return -1;
    }
    if (cmsg->cmsg_type != SCM_RIGHTS) {
      std::cerr << "invalid cmsg_type " << cmsg->cmsg_type << std::endl;
      return -1;
    }
    int *fd_p = (int *)CMSG_DATA(cmsg);
    fd = *fd_p;
  } else {
    fd = -1;
  }

  return (fd);
}

LightningClient::LightningClient(const std::string &store_socket,
                                 const std::string &password) {
  // setup unix domain socket with storage
  store_conn_ = socket(AF_UNIX, SOCK_STREAM, 0);
  if (store_conn_ < 0) {
    perror("cannot socket");
    exit(-1);
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  strncpy(addr.sun_path, store_socket.c_str(), store_socket.size());
  addr.sun_family = AF_UNIX;
  int status = connect(store_conn_, (struct sockaddr *)&addr, sizeof(addr));
  if (status < 0) {
    perror("cannot connect to the store");
    exit(-1);
  }

  pid_ = getpid();

  int nbytes_sent = send(store_conn_, &pid_, sizeof(pid_), 0);
  if (nbytes_sent != sizeof(pid_)) {
    perror("error sending pid");
    exit(-1);
  }

  int nbytes_recv = recv(store_conn_, &size_, sizeof(size_), 0);
  if (nbytes_recv != sizeof(size_)) {
    perror("error receiving the size of the object store");
    exit(-1);
  }

  int password_length = password.length();
  nbytes_sent = send(store_conn_, &password_length, sizeof(password_length), 0);
  if (nbytes_sent != sizeof(pid_)) {
    perror("error sending password length");
    exit(-1);
  }

  nbytes_sent = send(store_conn_, password.c_str(), password_length, 0);
  if (nbytes_sent != password_length) {
    perror("error sending password");
    exit(-1);
  }

  bool ok = false;

  nbytes_recv = recv(store_conn_, &ok, sizeof(bool), 0);
  if (nbytes_recv != sizeof(bool)) {
    perror("error receiving the ok bit");
    exit(-1);
  }

  if (!ok) {
    std::cerr << "authorization failure!" << std::endl;
    exit(-1);
  }

  store_fd_ = recv_fd(store_conn_);
  if (store_fd_ < 0) {
    perror("cannot open shared memory");
    exit(-1);
  }

  base_ = (uint8_t *)0xabcd000;

  header_ = (LightningStoreHeader *)mmap((void *)base_, size_, PROT_WRITE,
                                         MAP_SHARED | MAP_FIXED, store_fd_, 0);

  if (header_ != (LightningStoreHeader *)base_) {
    perror("mmap failed");
    exit(-1);
  }

  auto pid_str = "object-log-" + std::to_string(pid_);
  size_t object_log_size = sizeof(LogObjectEntry) * OBJECT_LOG_SIZE;
  object_log_fd_ = shm_open(pid_str.c_str(), O_CREAT | O_RDWR, 0666);

  status = ftruncate(object_log_fd_, object_log_size);
  if (status < 0) {
    perror("cannot ftruncate");
    exit(-1);
  }

  uint8_t *object_log_base = base_ + size_;

  object_log_base_ =
      (uint8_t *)mmap(object_log_base, object_log_size, PROT_WRITE,
                      MAP_SHARED | MAP_FIXED, object_log_fd_, 0);

  if (object_log_base_ != object_log_base) {
    perror("mmap failed");
    exit(-1);
  }

  disk_ = new UndoLogDisk(1024 * 1024 * 10, base_, size_ + object_log_size);
  object_log_ = new ObjectLog(object_log_base_, size_, disk_);

  allocator_ = new MemAllocator(header_, disk_);

  // page alignment check
  assert((size_t)base_ % 4096 == 0);
  // flush pages to reduce page faults; also do in the cache-friendly way
  volatile char checksum = 0;
  for (long i = size_ - 4096; i >= 0; i -= 4096)
    checksum ^= base_[i];

#ifdef USE_MPK
  init_mpk();
#endif

  std::cout << "header_ = " << (unsigned long)base_ << std::endl;
}

void LightningClient::init_mpk() {
  std::lock_guard<std::mutex> guard(pkey_lock_);
  if (pkey_ == -1) {
    std::cout << std::this_thread::get_id() << std::endl;
    pkey_ = pkey_alloc(0, 0);
    std::cout << "pkey = " << pkey_ << std::endl;
    int status = pkey_set(pkey_, PKEY_DISABLE_ACCESS);
    assert(status >= 0);
    status = pkey_mprotect(base_, sizeof(LightningStoreHeader),
                           PROT_READ | PROT_WRITE, pkey_);
    assert(status >= 0);
  }
}

void mpk_lock() {
#ifdef USE_MPK
  pkey_set(pkey_, PKEY_DISABLE_ACCESS);
#endif
}

void mpk_unlock() {
#ifdef USE_MPK
  pkey_set(pkey_, 0);
#endif
}

int LightningClient::Create(uint64_t object_id, uint8_t **ptr, size_t size) {
  mpk_unlock();
  LOCK;
  disk_->BeginTx();
  sm_offset offset;
  int status = create_internal(object_id, &offset, size);
  // status -1: object_id already exists
  if (status != -1) {
    assert(status == 0);
    *ptr = &base_[offset];
  }
  disk_->CommitTx();
  UNLOCK;
  mpk_lock();
  return status;
}

int64_t LightningClient::find_object(uint64_t object_id) {
  int64_t head_index =
      header_->hashmap.hash_entries[object_id % 65536].object_list;
  int64_t current_index = head_index;

  while (current_index >= 0) {
    ObjectEntry *current = &header_->object_entries[current_index];
    if (current->object_id == object_id) {
      return current_index;
    }
    current_index = current->next;
  }

  return -1;
}

int64_t LightningClient::alloc_object_entry() {
  int64_t i = header_->object_entry_free_list;
  LOGGED_WRITE(header_->object_entry_free_list,
               header_->object_entries[i].free_list_next, header_, disk_);
  // header_->object_entry_free_list =
  // header_->object_entries[i].free_list_next;

  LOGGED_WRITE(header_->object_entries[i].free_list_next, -1, header_, disk_);
  // header_->object_entries[i].free_list_next = -1;
  return i;
}

void LightningClient::dealloc_object_entry(int64_t i) {
  int64_t j = header_->object_entry_free_list;
  LOGGED_WRITE(header_->object_entries[i].free_list_next, j, header_, disk_);
  // header_->object_entries[i].free_list_next = j;

  LOGGED_WRITE(header_->object_entry_free_list, i, header_, disk_);
  // header_->object_entry_free_list = i;
}

int LightningClient::create_internal(uint64_t object_id, sm_offset *offset_ptr,
                                     size_t size) {
  int64_t object_index = find_object(object_id);

  if (object_index >= 0) {
    ObjectEntry *object = &header_->object_entries[object_index];
    if (object->offset > 0) {
      // object is already created
      return -1;
    }
    sm_offset object_buffer_offset = allocator_->MallocShared(size);

    LOGGED_WRITE(object->offset, object_buffer_offset, header_, disk_);
    // object->offset = object_buffer_offset;

    LOGGED_WRITE(object->size, size, header_, disk_);
    // object->size = size;

    LOGGED_WRITE(object->ref_count, 1, header_, disk_);
    // object->ref_count = 1;

    *offset_ptr = object_buffer_offset;
    object_log_->OpenObject(object_id);

    return 0;
  }

  int64_t new_object_index = alloc_object_entry();
  sm_offset object_buffer_offset = allocator_->MallocShared(size);
  ObjectEntry *new_object = &header_->object_entries[new_object_index];
  uint8_t *object_buffer = &base_[object_buffer_offset];

  LOGGED_WRITE(new_object->object_id, object_id, header_, disk_);
  // new_object->object_id = object_id;

  LOGGED_WRITE(new_object->num_waiters, 0, header_, disk_);
  // new_object->num_waiters = 0;

  LOGGED_WRITE(new_object->offset, object_buffer_offset, header_, disk_);
  // new_object->offset = object_buffer_offset;

  LOGGED_WRITE(new_object->size, size, header_, disk_);
  // new_object->size = size;

  LOGGED_WRITE(new_object->ref_count, 1, header_, disk_);
  // new_object->ref_count = 1;

  LOGGED_WRITE(new_object->sealed, false, header_, disk_);
  // new_object->sealed = false;

  int64_t head_index =
      header_->hashmap.hash_entries[object_id % 65536].object_list;
  ObjectEntry *head = &header_->object_entries[head_index];

  LOGGED_WRITE(new_object->next, head_index, header_, disk_);
  // new_object->next = head_index;

  LOGGED_WRITE(new_object->prev, -1, header_, disk_);
  // new_object->prev = -1;

  if (head_index >= 0) {
    LOGGED_WRITE(head->prev, new_object_index, header_, disk_);
    // head->prev = new_object_index;
  }

  LOGGED_WRITE(header_->hashmap.hash_entries[object_id % 65536].object_list,
               new_object_index, header_,
               disk_); // header_->hashmap.hash_entries[object_id %
                       // 65536].object_list = new_object_index;

  *offset_ptr = object_buffer_offset;

  object_log_->OpenObject(object_id);

  return 0;
}

void RepetitiveSemPost(sem_t *sem, int n) {
  for (int i = 0; i < n; i++) {
    assert(sem_post(sem) == 0);
  }
}

int LightningClient::seal_internal(uint64_t object_id) {
  int64_t object_index = find_object(object_id);
  assert(object_index >= 0);

  ObjectEntry *object_entry = &header_->object_entries[object_index];

  LOGGED_WRITE(object_entry->sealed, true, header_, disk_);
  // object_entry->sealed = true;

  if (object_entry->num_waiters > 0) {
    RepetitiveSemPost(&object_entry->sem, object_entry->num_waiters);
    /*
    for (int i = 0; i < object_entry->num_waiters; i++) {
      assert(sem_post(&object_entry->sem) == 0);
    }
    */
    LOGGED_WRITE(object_entry->num_waiters, 0, header_, disk_);
    // object_entry->num_waiters = 0;
    assert(sem_destroy(&object_entry->sem) == 0);
  }
  return 0;
}

int LightningClient::Seal(uint64_t object_id) {
  mpk_unlock();
  LOCK;
  int status = seal_internal(object_id);
  UNLOCK;
  mpk_lock();
  return status;
}

int LightningClient::get_internal(uint64_t object_id, sm_offset *offset_ptr,
                                  size_t *size) {
  int64_t object_index = find_object(object_id);

  if (object_index < 0) {
    // object not found
    return -1;
  }

  ObjectEntry *object_entry = &header_->object_entries[object_index];

  if (!object_entry->sealed) {
    // object is not sealed yet
    return -1;
  }

  *offset_ptr = object_entry->offset;
  *size = object_entry->size;

  LOGGED_WRITE(object_entry->ref_count, object_entry->ref_count + 1, header_,
               disk_);
  // object_entry->ref_count++;

  object_log_->OpenObject(object_id);

  return 0;
}

int LightningClient::Get(uint64_t object_id, uint8_t **ptr, size_t *size) {
  mpk_unlock();
  LOCK;
  disk_->BeginTx();
  sm_offset offset;
  int status = get_internal(object_id, &offset, size);
  if (status == 0) {
    *ptr = &base_[offset];
  }
  disk_->CommitTx();
  UNLOCK;
  mpk_lock();
  return status;
}

int LightningClient::Release(uint64_t object_id) {
  mpk_unlock();
  LOCK;

  int64_t object_index = find_object(object_id);
  assert(object_index >= 0);

  ObjectEntry *object_entry = &header_->object_entries[object_index];
  assert(object_entry->sealed);

  object_log_->CloseObject(object_id);

  LOGGED_WRITE(object_entry->ref_count, object_entry->ref_count - 1, header_,
               disk_);
  // object_entry->ref_count--;

  if (object_entry->ref_count == 0) {
    allocator_->FreeShared(object_entry->offset);
    int64_t prev_object_index = object_entry->prev;
    int64_t next_object_index = object_entry->next;

    if (prev_object_index < 0) {
      if (next_object_index >= 0) {
        ObjectEntry *next = &header_->object_entries[next_object_index];

        LOGGED_WRITE(next->prev, -1, header_, disk_);
        // next->prev = -1;
      }

      LOGGED_WRITE(header_->hashmap.hash_entries[object_id % 65536].object_list,
                   next_object_index, header_, disk_);
      // header_->hashmap.hash_entries[object_id % 65536].object_list =
      //     next_object_index;
    } else {
      ObjectEntry *prev = &header_->object_entries[prev_object_index];
      LOGGED_WRITE(prev->next, next_object_index, header_, disk_);
      // prev->next = next_object_index;
      if (next_object_index >= 0) {
        ObjectEntry *next = &header_->object_entries[next_object_index];

        LOGGED_WRITE(next->prev, prev_object_index, header_, disk_);
        next->prev = prev_object_index;
      }
    }
    dealloc_object_entry(object_index);
  }
  UNLOCK;
  mpk_lock();
  return 0;
}

int LightningClient::delete_internal(uint64_t object_id) {
  int64_t object_index = find_object(object_id);
  assert(object_index >= 0);

  ObjectEntry *object_entry = &header_->object_entries[object_index];
  assert(object_entry->sealed);
  object_log_->CloseObject(object_id);
  allocator_->FreeShared(object_entry->offset);
  int64_t prev_object_index = object_entry->prev;
  int64_t next_object_index = object_entry->next;

  if (prev_object_index < 0) {
    if (next_object_index > 0) {
      ObjectEntry *next = &header_->object_entries[next_object_index];
      LOGGED_WRITE(next->prev, -1, header_, disk_);
      // next->prev = -1;
    }
    LOGGED_WRITE(header_->hashmap.hash_entries[object_id % 65536].object_list,
                 next_object_index, header_, disk_);
    /*
    header_->hashmap.hash_entries[object_id % 65536].object_list =
        next_object_index;
    */
  } else {
    ObjectEntry *prev = &header_->object_entries[prev_object_index];

    LOGGED_WRITE(prev->next, next_object_index, header_, disk_);
    // prev->next = next_object_index;

    if (next_object_index >= 0) {
      ObjectEntry *next = &header_->object_entries[next_object_index];

      LOGGED_WRITE(next->prev, prev_object_index, header_, disk_);
      // next->prev = prev_object_index;
    }
  }
  dealloc_object_entry(object_index);

  return 0;
}

int LightningClient::Delete(uint64_t object_id) {
  mpk_unlock();
  LOCK;
  disk_->BeginTx();
  int status = delete_internal(object_id);
  disk_->CommitTx();
  UNLOCK;
  mpk_lock();
  return status;
}

int LightningClient::MultiPut(uint64_t object_id,
                              std::vector<std::string> fields,
                              std::vector<int64_t> subobject_sizes,
                              std::vector<uint8_t *> subobjects) {
  int64_t num_subobjects = fields.size();

  assert(num_subobjects >= 1);
  assert(num_subobjects == subobject_sizes.size());
  assert(num_subobjects == subobjects.size());

  int sum_field_name = 0;
  int sum_content_size = 0;
  for (int i = 0; i < num_subobjects; i++) {
    sum_field_name += fields[i].length();
    sum_content_size += subobject_sizes[i];
  }
  int object_size = sizeof(int64_t) + num_subobjects * 2 * sizeof(int64_t) +
                    sum_field_name + sum_content_size;
  uint8_t *ptr = nullptr;

  mpk_unlock();
  LOCK;
  disk_->BeginTx();
  sm_offset offset;
  int status = create_internal(object_id, &offset, object_size);
  assert(status == 0);
  ptr = &base_[offset];
  disk_->CommitTx();

  int64_t *meta_ptr = (int64_t *)ptr;
  int64_t metadata_offset =
      sizeof(int64_t) + num_subobjects * 2 * sizeof(int64_t);
  int64_t content_offset =
      sizeof(int64_t) + num_subobjects * 2 * sizeof(int64_t) + sum_field_name;
  meta_ptr[0] = num_subobjects;
  for (int i = 0; i < num_subobjects; i++) {
    assert(subobject_sizes[i] > 0);
    meta_ptr[2 * i + 1] = metadata_offset + fields[i].length();
    meta_ptr[2 * i + 2] = content_offset + subobject_sizes[i];
    memcpy(ptr + metadata_offset, fields[i].c_str(), fields[i].length());
    memcpy(ptr + content_offset, subobjects[i], subobject_sizes[i]);
    metadata_offset = meta_ptr[2 * i + 1];
    content_offset = meta_ptr[2 * i + 2];
  }

  disk_->BeginTx();
  seal_internal(object_id);
  disk_->CommitTx();
  UNLOCK;
  mpk_lock();
  return 0;
}

int LightningClient::MultiUpdate(uint64_t object_id,
                                 std::vector<std::string> fields,
                                 std::vector<int64_t> subobject_sizes,
                                 std::vector<uint8_t *> subobjects) {
  int64_t num_subobjects = fields.size();

  assert(num_subobjects >= 1);
  assert(num_subobjects == subobject_sizes.size());
  assert(num_subobjects == subobjects.size());

  mpk_unlock();
  LOCK;
  disk_->BeginTx();
  int status = delete_internal(object_id);
  assert(status == 0);
  disk_->CommitTx();

  int sum_field_name = 0;
  int sum_content_size = 0;
  for (int i = 0; i < num_subobjects; i++) {
    sum_field_name += fields[i].length();
    sum_content_size += subobject_sizes[i];
  }
  int object_size = sizeof(int64_t) + num_subobjects * 2 * sizeof(int64_t) +
                    sum_field_name + sum_content_size;
  uint8_t *ptr = nullptr;
  disk_->BeginTx();
  sm_offset offset;
  status = create_internal(object_id, &offset, object_size);
  assert(status == 0);
  disk_->CommitTx();

  ptr = &base_[offset];
  int64_t *meta_ptr = (int64_t *)ptr;
  int64_t metadata_offset =
      sizeof(int64_t) + num_subobjects * 2 * sizeof(int64_t);
  int64_t content_offset =
      sizeof(int64_t) + num_subobjects * 2 * sizeof(int64_t) + sum_field_name;
  meta_ptr[0] = num_subobjects;
  for (int i = 0; i < num_subobjects; i++) {
    assert(subobject_sizes[i] > 0);
    meta_ptr[2 * i + 1] = metadata_offset + fields[i].length();
    meta_ptr[2 * i + 2] = content_offset + subobject_sizes[i];
    memcpy(ptr + metadata_offset, fields[i].c_str(), fields[i].length());
    memcpy(ptr + content_offset, subobjects[i], subobject_sizes[i]);
    metadata_offset = meta_ptr[2 * i + 1];
    content_offset = meta_ptr[2 * i + 2];
  }

  disk_->BeginTx();
  seal_internal(object_id);
  disk_->CommitTx();
  UNLOCK;
  mpk_lock();
  return 0;
}

int LightningClient::MultiGet(uint64_t object_id,
                              std::vector<std::string> in_fields,
                              std::vector<int64_t> *out_field_sizes,
                              std::vector<uint8_t *> *out_fields,
                              std::vector<int64_t> *subobject_sizes,
                              std::vector<uint8_t *> *subobjects) {
  uint8_t *ptr;
  size_t size;
  mpk_unlock();

  LOCK;
  disk_->BeginTx();
  sm_offset offset;

  int status = get_internal(object_id, &offset, &size);
  assert(status == 0);
  disk_->CommitTx();

  ptr = &base_[offset];

  int64_t *meta_ptr = (int64_t *)ptr;

  int64_t num_subobjects = meta_ptr[0];

  bool fetch_all = in_fields.empty();

  if (fetch_all) {
    int64_t metadata_offset =
        sizeof(int64_t) + num_subobjects * 2 * sizeof(int64_t);
    int64_t content_offset = meta_ptr[2 * num_subobjects - 1];

    out_field_sizes->reserve(num_subobjects);
    out_fields->reserve(num_subobjects);
    subobject_sizes->reserve(num_subobjects);
    subobjects->reserve(num_subobjects);

    for (int i = 0; i < num_subobjects; i++) {
      assert(meta_ptr[2 * i + 2] - content_offset > 0);
      (*out_fields)[i] = (ptr + metadata_offset);
      (*out_field_sizes)[i] = (meta_ptr[2 * i + 1] - meta_ptr[2 * i + 1]);
      (*subobject_sizes)[i] = (content_offset);
      (*subobjects)[i] = (ptr + meta_ptr[2 * i + 2] - content_offset);

      metadata_offset = meta_ptr[2 * i + 1];
      content_offset = meta_ptr[2 * i + 2];
    }

  } else {
    std::unordered_map<std::string,
                       std::tuple<int64_t, int64_t, int64_t, int64_t>>
        m;

    int64_t metadata_offset =
        sizeof(int64_t) + num_subobjects * 2 * sizeof(int64_t);

    int64_t content_offset = meta_ptr[2 * num_subobjects - 1];

    for (int i = 0; i < num_subobjects; i++) {
      std::string field((char *)ptr + metadata_offset,
                        meta_ptr[2 * i + 1] - metadata_offset);
      assert(meta_ptr[2 * i + 2] - content_offset > 0);
      m[field] = {metadata_offset, meta_ptr[2 * i + 1] - meta_ptr[2 * i + 1],
                  content_offset, meta_ptr[2 * i + 2] - content_offset};
      metadata_offset = meta_ptr[2 * i + 1];
      content_offset = meta_ptr[2 * i + 2];
    }

    for (const auto &field : in_fields) {
      auto search = m.find(field);
      if (search == m.end()) {
        continue;
      }
      out_fields->push_back(ptr + std::get<0>(m[field]));
      out_field_sizes->push_back(std::get<1>(m[field]));
      subobject_sizes->push_back(std::get<3>(m[field]));
      subobjects->push_back(ptr + std::get<2>(m[field]));
    }
  }

  UNLOCK;
  mpk_lock();
  return 0;
}

int LightningClient::subscribe_internal(uint64_t object_id, sem_t **sem,
                                        bool *wait) {
  int64_t object_index = find_object(object_id);
  if (object_index < 0) {
    int64_t new_object_index = alloc_object_entry();
    ObjectEntry *new_object = &header_->object_entries[new_object_index];

    LOGGED_WRITE(new_object->object_id, object_id, header_, disk_);
    // new_object->object_id = object_id;

    // this means the object is not created
    LOGGED_WRITE(new_object->offset, -1, header_, disk_);
    // new_object->offset = -1;

    LOGGED_WRITE(new_object->sealed, false, header_, disk_);
    // new_object->sealed = false;

    assert(sem_init(&new_object->sem, 1, 0) == 0);

    LOGGED_WRITE(new_object->num_waiters, 1, header_, disk_);
    // new_object->num_waiters = 1;

    int64_t head_index =
        header_->hashmap.hash_entries[object_id % 65536].object_list;
    ObjectEntry *head = &header_->object_entries[head_index];

    LOGGED_WRITE(new_object->next, head_index, header_, disk_);
    // new_object->next = head_index;

    LOGGED_WRITE(new_object->prev, -1, header_, disk_);
    // new_object->prev = -1;

    if (head_index > 0) {
      LOGGED_WRITE(head->prev, new_object_index, header_, disk_);
      // head->prev = new_object_index;
    }

    LOGGED_WRITE(header_->hashmap.hash_entries[object_id % 65536].object_list,
                 new_object_index, header_, disk_);
    // header_->hashmap.hash_entries[object_id % 65536].object_list =
    //     new_object_index;

    *sem = &new_object->sem;

    *wait = true;

    return 0;
  }

  ObjectEntry *object = &header_->object_entries[object_index];
  if (object->sealed) {
    *wait = false;
    return 0;
  }

  LOGGED_WRITE(object->num_waiters, object->num_waiters + 1, header_, disk_);
  // object->num_waiters++;

  *sem = &object->sem;
  *wait = true;

  return 0;
}

int LightningClient::Subscribe(uint64_t object_id) {
  mpk_unlock();
  LOCK;

  disk_->BeginTx();
  sem_t *sem;
  bool wait;
  int status = subscribe_internal(object_id, &sem, &wait);
  disk_->CommitTx();
  UNLOCK;
  if (wait) {
    assert(sem_wait(sem) == 0);
  }
  mpk_lock();
  return status;
}
