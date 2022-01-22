#include <assert.h>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <signal.h>
#include <stdlib.h>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <unordered_set>
#include <vector>

#include "log_disk.h"
#include "object_log.h"
#include "store.h"

const char *name = "lightning";

void signal_handler(int sig_number) {
  std::cout << "Capture Ctrl+C" << std::endl;
  exit(0);
}

int send_fd(int unix_sock, int fd) {
  ssize_t size;
  struct msghdr msg;
  struct iovec iov;
  union {
    struct cmsghdr cmsghdr;
    char control[CMSG_SPACE(sizeof(int))];
  } cmsgu;
  struct cmsghdr *cmsg;
  char buf[2];

  iov.iov_base = buf;
  iov.iov_len = 2;

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  if (fd != -1) {
    msg.msg_control = cmsgu.control;
    msg.msg_controllen = sizeof(cmsgu.control);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;

    int *fd_p = (int *)CMSG_DATA(cmsg);
    *fd_p = fd;
  } else {
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
  }

  size = sendmsg(unix_sock, &msg, 0);

  if (size < 0) {
    std::cerr << "recvmsg error" << std::endl;
  }
  return size;
}

LightningStore::LightningStore(const std::string &unix_socket, int size)
    : unix_socket_(unix_socket), size_(size) {
  store_fd_ = shm_open(name, O_CREAT | O_RDWR, 0666);
  int status = ftruncate(store_fd_, size);
  if (status < 0) {
    perror("cannot ftruncate");
    exit(-1);
  }
  store_header_ =
      (LightningStoreHeader *)mmap((void *)0xabcd000, size, PROT_WRITE,
                                   MAP_SHARED | MAP_FIXED, store_fd_, 0);
  if (store_header_ == (LightningStoreHeader *)-1) {
    perror("mmap failed");
    exit(-1);
  }

  shm_unlink(name);

  std::cout << "store_header_ = " << (unsigned long)store_header_ << std::endl;

  store_header_ = new (store_header_) LightningStoreHeader;

  for (int i = 0; i < MAX_NUM_OBJECTS - 1; i++) {
    store_header_->memory_entries[i].free_list_next = i + 1;
  }
  store_header_->memory_entries[MAX_NUM_OBJECTS - 1].free_list_next = -1;

  for (int i = 0; i < MAX_NUM_OBJECTS - 1; i++) {
    store_header_->object_entries[i].free_list_next = i + 1;
  }
  store_header_->object_entries[MAX_NUM_OBJECTS - 1].free_list_next = -1;

  allocator_ = new MemAllocator((LightningStoreHeader *)store_header_, nullptr);

  int num_mpk_pages = sizeof(LightningStoreHeader) / 4096 + 1;

  int64_t secure_memory_size = num_mpk_pages * 4096;

  allocator_->Init(secure_memory_size, size - secure_memory_size);

  for (int i = 0; i < HASHMAP_SIZE; i++) {
    store_header_->hashmap.hash_entries[i].object_list = -1;
  }
}

int64_t LightningStore::find_object(uint64_t object_id) {
  int64_t head_index =
      store_header_->hashmap.hash_entries[object_id % 65536].object_list;
  int64_t current_index = head_index;

  while (current_index >= 0) {
    ObjectEntry *current = &store_header_->object_entries[current_index];
    if (current->object_id == object_id) {
      return current_index;
    }
    current_index = current->next;
  }

  return -1;
}

int LightningStore::release_object(uint64_t object_id) {
  uint8_t *base = (uint8_t *)store_header_;

  int64_t object_index = find_object(object_id);
  assert(object_index >= 0);

  ObjectEntry *object_entry = &store_header_->object_entries[object_index];
  object_entry->ref_count--;
  if (object_entry->ref_count == 0) {
    allocator_->FreeSharedNoLog(object_entry->offset);
    int64_t prev_object_index = object_entry->prev;
    int64_t next_object_index = object_entry->next;

    if (prev_object_index < 0) {
      if (next_object_index >= 0) {
        ObjectEntry *next = &store_header_->object_entries[next_object_index];
        next->prev = -1;
      }
      store_header_->hashmap.hash_entries[object_id % 65536].object_list =
          next_object_index;
    } else {
      ObjectEntry *prev = &store_header_->object_entries[prev_object_index];
      prev->next = next_object_index;
      if (next_object_index >= 0) {
        ObjectEntry *next = &store_header_->object_entries[next_object_index];
        next->prev = prev_object_index;
      }
    }

    int64_t j = store_header_->object_entry_free_list;
    store_header_->object_entries[object_index].free_list_next = j;
    store_header_->object_entry_free_list = object_index;
  }
  return 0;
}

void LightningStore::recover(uint8_t *base, uint8_t *log, uint8_t *object_log,
                             pid_t pid) {
  int hashmap_size = sizeof(LogObjectEntry) * OBJECT_LOG_SIZE;
  if (store_header_->lock_flag == pid) {
    std::cout << "undo log will be replayed!" << std::endl;
    uint64_t log_length = *(uint64_t *)log;

    if (log_length > 0) {
      for (uint64_t i = log_length - 1; i >= 0; i--) {
        uint64_t offset = i * sizeof(LogEntry) + sizeof(uint64_t);
        LogEntry *entry = (LogEntry *)&log[offset];
        uint64_t *ptr = (uint64_t *)&base[entry->offset];
        *ptr = entry->value;
        if (i == 0) {
          break;
        }
      }
    }
  } else {
    while (!__sync_bool_compare_and_swap(&store_header_->lock_flag, 0, 1)) {
      nanosleep((const struct timespec[]){{0, 0L}}, NULL);
    }
  }

  // garbage collect open objects
  LogObjectEntry *objects = (LogObjectEntry *)object_log;
  for (int i = 0; i < OBJECT_LOG_SIZE; i++) {
    if (objects[i].in_use) {
      // std::cout << "releasing object " << objects[i].object_id << std::endl;
      release_object(objects[i].object_id);
    }
  }

  std::atomic_thread_fence(std::memory_order_release);
  store_header_->lock_flag = 0;
}

bool is_number(char *str) {
  while (*str != '\0') {
    if (!std::isdigit(*str)) {
      return false;
    }
    str++;
  }
  return true;
}

void get_processes(std::unordered_set<pid_t> *processes) {
  DIR *dp = opendir("/proc");

  if (dp == nullptr) {
    std::cerr << "cannot access procfs!" << std::endl;
  }

  struct dirent *dirp = readdir(dp);
  while (dirp != nullptr) {
    if (is_number(dirp->d_name)) {
      processes->insert(std::atoi(dirp->d_name));
    }

    dirp = readdir(dp);
  }

  closedir(dp);
}

void LightningStore::monitor() {
  while (true) {
    {
      // scan the set of clients to find crashed ones
      std::lock_guard<std::mutex> guard(client_lock_);
      std::unordered_set<pid_t> processes;
      get_processes(&processes);

      for (pid_t pid : clients_) {
        auto got = processes.find(pid);
        if (got == processes.end()) {
          std::cout << "pid = " << pid << " crashes! start recovering!"
                    << std::endl;
          // map object log into memory

          auto object_log_name = "object-log-" + std::to_string(pid);
          int object_log_fd =
              shm_open(object_log_name.c_str(), O_CREAT | O_RDWR, 0666);
          int object_log_size = sizeof(LogObjectEntry) * OBJECT_LOG_SIZE;
          int status = ftruncate(object_log_fd, object_log_size);
          uint8_t *base = (uint8_t *)store_header_;
          uint8_t *object_log_base = base + size_;
          object_log_base =
              (uint8_t *)mmap(object_log_base, object_log_size, PROT_WRITE,
                              MAP_SHARED | MAP_FIXED, object_log_fd, 0);
          if (object_log_base != base + size_) {
            perror("mmap failure");
            exit(-1);
          }

          // map client log into memory
          auto name = "log-" + std::to_string(pid);
          int log_fd = shm_open(name.c_str(), O_CREAT | O_RDWR, 0666);
          // log is 1MB large
          int size = 1024 * 1024 * 10;
          status = ftruncate(log_fd, size);
          uint8_t *log_base =
              (uint8_t *)mmap(nullptr, size, PROT_WRITE, MAP_SHARED, log_fd, 0);
          auto start = std::chrono::high_resolution_clock::now();

          recover((uint8_t *)store_header_, log_base, object_log_base, pid);
          munmap(log_base, size);
          close(log_fd);
          shm_unlink(name.c_str());
          munmap(object_log_base, object_log_size);
          close(object_log_fd);
          shm_unlink(object_log_name.c_str());

          clients_.erase(pid);
          auto end = std::chrono::high_resolution_clock::now();
          std::chrono::duration<double> duration = end - start;

          std::cout << "recovered using " << duration.count() << " s!"
                    << std::endl;
        }
      }
    }
    usleep(1000000);
  }
}

int64_t LightningStore::alloc_object_entry() {
  int64_t i = store_header_->object_entry_free_list;
  store_header_->object_entry_free_list =
      store_header_->object_entries[i].free_list_next;
  store_header_->object_entries[i].free_list_next = -1;
  return i;
}

void LightningStore::dealloc_object_entry(int64_t i) {
  int64_t j = store_header_->object_entry_free_list;
  store_header_->object_entries[i].free_list_next = j;
  store_header_->object_entry_free_list = i;
}

int LightningStore::create_object(uint64_t object_id, sm_offset *offset_ptr,
                                  size_t size) {
  int64_t object_index = find_object(object_id);

  if (object_index >= 0) {
    ObjectEntry *object = &store_header_->object_entries[object_index];
    if (object->offset > 0) {
      // object is already created
      return -1;
    }
    sm_offset object_buffer_offset = allocator_->MallocShared(size);

    object->offset = object_buffer_offset;
    object->size = size;
    object->ref_count = 1;
    *offset_ptr = object_buffer_offset;

    return 0;
  }

  int64_t new_object_index = alloc_object_entry();
  sm_offset object_buffer_offset = allocator_->MallocShared(size);
  ObjectEntry *new_object = &store_header_->object_entries[new_object_index];
  // uint8_t *object_buffer = &base_[object_buffer_offset];

  new_object->object_id = object_id;
  new_object->num_waiters = 0;
  new_object->offset = object_buffer_offset;
  new_object->size = size;
  new_object->ref_count = 1;
  new_object->sealed = false;

  int64_t head_index =
      store_header_->hashmap.hash_entries[object_id % 65536].object_list;
  ObjectEntry *head = &store_header_->object_entries[head_index];

  new_object->next = head_index;
  new_object->prev = -1;

  if (head_index >= 0) {
    head->prev = new_object_index;
  }
  store_header_->hashmap.hash_entries[object_id % 65536].object_list =
      new_object_index;

  *offset_ptr = object_buffer_offset;
  return 0;
}

int LightningStore::seal_object(uint64_t object_id) {
  int64_t object_index = find_object(object_id);
  assert(object_index >= 0);

  ObjectEntry *object_entry = &store_header_->object_entries[object_index];
  object_entry->sealed = true;
  return 0;
}

int LightningStore::get_object(uint64_t object_id, sm_offset *ptr,
                               size_t *size) {
  int64_t object_index = find_object(object_id);
  if (object_index < 0) {
    // object not found
    return -1;
  }
  ObjectEntry *object_entry = &store_header_->object_entries[object_index];

  if (!object_entry->sealed) {
    // object is not sealed yet
    return -1;
  }
  *ptr = object_entry->offset;
  *size = object_entry->size;
  object_entry->ref_count++;

  return 0;
}

int LightningStore::delete_object(uint64_t object_id) {
  int64_t object_index = find_object(object_id);
  assert(object_index >= 0);

  ObjectEntry *object_entry = &store_header_->object_entries[object_index];
  assert(object_entry->sealed);
  allocator_->FreeShared(object_entry->offset);
  int64_t prev_object_index = object_entry->prev;
  int64_t next_object_index = object_entry->next;

  if (prev_object_index < 0) {
    if (next_object_index > 0) {
      ObjectEntry *next = &store_header_->object_entries[next_object_index];
      next->prev = -1;
    }
    store_header_->hashmap.hash_entries[object_id % 65536].object_list =
        next_object_index;
  } else {
    ObjectEntry *prev = &store_header_->object_entries[prev_object_index];
    prev->next = next_object_index;

    if (next_object_index >= 0) {
      ObjectEntry *next = &store_header_->object_entries[next_object_index];
      next->prev = prev_object_index;
    }
  }
  dealloc_object_entry(object_index);

  return 0;
}

void LightningStore::listener() {
  int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server_fd < 0) {
    perror("cannot create socket");
    exit(-1);
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, unix_socket_.c_str(), unix_socket_.size());
  unlink(unix_socket_.c_str());

  int status = bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
  if (status < 0) {
    perror("cannot bind");
    exit(-1);
  }

  status = listen(server_fd, 0);
  if (status < 0) {
    perror("cannot listen");
    exit(-1);
  }

  std::cout << "Store is ready!" << std::endl;

  while (true) {
    int client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd < 0) {
      perror("cannot accept");
      exit(-1);
    }

    pid_t pid;
    int bytes_read = recv(client_fd, &pid, sizeof(pid), 0);
    if (bytes_read != sizeof(pid)) {
      perror("failure reading pid from unix domain socket!");
      exit(-1);
    }

    int bytes_sent = send(client_fd, &size_, sizeof(size_), 0);
    if (bytes_sent != sizeof(size_)) {
      perror("failure sending the size of the object store");
      exit(-1);
    }

    int password_length = 0;

    bytes_read = recv(client_fd, &password_length, sizeof(password_length), 0);
    if (bytes_read != sizeof(password_length)) {
      std::cerr << "failure receiving the password size" << std::endl;
      exit(-1);
    }

    char password[100];
    bytes_read = recv(client_fd, password, password_length, 0);
    if (bytes_read != password_length) {
      std::cerr << "failure receiving the password" << std::endl;
      exit(-1);
    }

    bool ok = false;

    if (strcmp(password, "password") == 0) {
      ok = true;
    }

    bytes_sent = send(client_fd, &ok, sizeof(ok), 0);
    if (bytes_sent != sizeof(ok)) {
      perror("failure sending the ok bit");
      exit(-1);
    }

    send_fd(client_fd, store_fd_);
    {
      std::lock_guard<std::mutex> guard(client_lock_);

      clients_.insert(pid);
    }
  }
}

void LightningStore::Run() {
  std::thread monitor_thread = std::thread(&LightningStore::monitor, this);
  std::thread listener_thread = std::thread(&LightningStore::listener, this);
  listener_thread.join();
  monitor_thread.join();
}

int main() {
  if (signal(SIGINT, signal_handler) == SIG_ERR) {
    std::cerr << "cannot register signal handler!" << std::endl;
    exit(-1);
  }

  LightningStore store("/tmp/lightning", 1024 * 1024 * 1024);
  store.Run();

  return 0;
}
