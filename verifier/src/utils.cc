#include <algorithm>
#include <cassert>

#include "utils.h"

extern "C" {
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
}

bool is_prefix(const std::string &s, const std::string &prefix) {
  auto res = std::mismatch(prefix.begin(), prefix.end(), s.begin());
  if (res.first == prefix.end()) {
    return true;
  }
  return false;
}

std::string NameFactory::GetUniqueName(const std::string &base_name) {
  std::lock_guard<std::mutex> lg(name_map_mutex_);
  if (name_map_.find(base_name) == name_map_.end()) {
    name_map_[base_name] = 0;
  }
  uint64_t cnt = name_map_[base_name];
  assert(cnt < 0xffffffffffffffffULL);
  name_map_[base_name] = cnt + 1;
  return base_name + "!" + std::to_string(cnt);
}

SubProcessFunc::SubProcessFunc(std::function<std::string()> f) : f_(f) {}

std::string SubProcessFunc::operator()() {
  pid_t pid;
  int pipe_fd[2];
  if (pipe(pipe_fd)) {
    throw Exception{"Pipe Failed"};
  }

  pid = fork();
  if (pid < (pid_t)0) {
    throw Exception{"Fork Failed"};
  }

  if (pid == (pid_t)0) {
    // child process
    close(pipe_fd[0]);
    auto str = f_();
    ssize_t offset = 0;
    ssize_t written = 0;
    const char *ptr = str.c_str();
    do {
      written = write(pipe_fd[1], &ptr[offset], str.size() - offset);
      if (written < 0) {
        exit(1);
      }
      offset += written;
    } while (offset < str.size());
    close(pipe_fd[1]);
    exit(0);
  } else {
    // parent process
    close(pipe_fd[1]);
    int ret_code = 0;
    ssize_t bytes_read = 0;
    char buf[65538];
    std::string result = "";
    do {
      bytes_read = read(pipe_fd[0], buf, 65536);
      if (bytes_read < 0) {
        throw Exception{"Pipe Reading Failed"};
      }
      result = result + std::string(buf, bytes_read);
    } while (bytes_read != 0);
    waitpid(pid, &ret_code, 0);
    if (ret_code != 0) {
      throw Exception{"Child Process Failed"};
    }
    close(pipe_fd[0]);
    return result;
  }
}
