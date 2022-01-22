#pragma once

#include <unordered_set>

#include "executor.h"
#include "llvm-helpers.h"
#include "llvm-incl.h"
#include "symbolic-expr.h"

extern std::string log_write_cnt_name;

class SymExecFunctions {
public:
  static std::unique_ptr<SymExecFunctions> instance;

  static SymExecFunctions *get();

  bool is_abstract_function(const std::string &func_name);

  StatePtrList run_function(std::shared_ptr<ExecutionState> s,
                            const std::string &func_name,
                            const std::string &dst_reg,
                            const std::vector<RegValue> &params);

  void add_readonly_function(const std::string &func_name);

  std::string log_write_func;
  std::unordered_map<std::string, int> log_write_bounds;

  bool counting_mode = false;

private:
  std::unordered_set<std::string> readonly_funcs_;

  NameFactory name_gen_;
};
