#include <algorithm>
#include <cctype>
#include <cxxabi.h>
#include <unordered_map>
#include <vector>

#include "llvm-helpers.h"
#include "utils.h"

std::vector<std::string> find_element_entry(llvm::Module *module,
                                            const std::string &element_name) {
  std::vector<std::string> patterns = {
      element_name + "::push(",
      element_name + "::pull(",
      element_name + "::simple_action(",
  };

  std::unordered_map<std::string, std::string> matched;

  for (auto iter = module->begin(); iter != module->end(); iter++) {
    auto func_name = iter->getName().str();
    size_t size = 0;
    int status = 0;
    char *n = abi::__cxa_demangle(func_name.c_str(), NULL, &size, &status);
    if (n != NULL) {
      std::string s(n);
      for (auto &pat : patterns) {
        if (is_prefix(s, pat)) {
          assert(matched.find(pat) == matched.end());
          matched[pat] = func_name;
        }
      }
    }
  }

  std::vector<std::string> vec;
  for (auto iter = matched.begin(); iter != matched.end(); iter++) {
    vec.push_back(iter->second);
  }

  return vec;
}

std::string get_type_name(llvm::Type *t) {
  std::string res;
  llvm::raw_string_ostream stream{res};
  t->print(stream);
  stream.str();

  // we only keep things before the first space
  auto found = res.find(' ');
  if (found != std::string::npos) {
    res = res.substr(0, found);
  }
  return res;
}

std::string llvm_type_to_str(llvm::Type *t) {
  std::string res;
  llvm::raw_string_ostream stream{res};
  t->print(stream);
  stream.str();
  return res;
}

uint64_t get_type_size(const llvm::Module *m, llvm::Type *type) {
  llvm::DataLayout *dl = new llvm::DataLayout(m);
  uint64_t type_size = dl->getTypeStoreSize(type);
  return type_size;
}

std::string get_name(const llvm::Value &value) {
  std::string res;
  llvm::raw_string_ostream stream{res};
  value.printAsOperand(stream, false);
  stream.str();
  return res;
}

int64_t get_int_val(const llvm::Value *value) {
  if (const llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(value)) {
    if (CI->getBitWidth() <= 64) {
      return CI->getSExtValue();
    }
  }
  assert(false && "not an integer constant");
}

std::string demangle_cpp_name(const std::string &cpp_name) {
  size_t size = 0;
  int status = 0;
  char *n = abi::__cxa_demangle(cpp_name.c_str(), NULL, &size, &status);
  if (n == NULL) {
    return "";
  } else {
    std::string s = n;
    free(n);
    return s;
  }
}

std::string trim(const std::string &s) {
  if (s == "") {
    return s;
  }
  auto start = s.find_first_not_of(" ");
  auto end = s.find_last_not_of(" ");
  return s.substr(start, end - start + 1);
}

std::vector<std::string> split_template(const std::string &id) {
  std::vector<std::string> type_args;
  std::string filtered;
  size_t curr_pos = 0;
  while (1) {
    // find the first '<'
    auto l = id.find('<', curr_pos);
    if (l == std::string::npos) {
      filtered = filtered + id.substr(curr_pos);
      goto out;
    }
    auto r = id.find('>', curr_pos);
    if (r == std::string::npos) {
      assert(false && "mismatched < and >");
    }
    size_t pos = l + 1;
    while (pos < r) {
      auto comma = id.find(',', pos);
      if (comma == std::string::npos || comma >= r) {
        type_args.push_back(id.substr(pos, r - pos));
        break;
      }
      type_args.push_back(id.substr(pos, comma - pos));
      pos = comma + 1;
    }
    filtered = filtered + id.substr(curr_pos, l - curr_pos);
    curr_pos = r + 1;
  }
out:
  std::vector<std::string> result;
  result.push_back(trim(filtered));
  for (int i = 0; i < type_args.size(); i++) {
    result.push_back(trim(type_args[i]));
  }
  return result;
}
