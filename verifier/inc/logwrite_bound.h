#pragma once

#include <functional>
#include <unordered_map>

#include "abstract-functions.h"
#include "executor.h"
#include "z3-gen.h"

struct LogWriteBound {
  int bound;
  std::function<Symbolic::ExprPtr(const std::vector<RegValue> &)> pre_cond;
  std::function<Symbolic::ExprPtr(const std::vector<RegValue> &, RegValue &)>
      post_cond;
};

class BoundRegistry {
public:
  static BoundRegistry *get();

  bool have_record(const std::string &fn) const;

  int find_bound(const std::string &fn, std::shared_ptr<ExecutionState> &s,
                 const std::vector<RegValue> &params, LogWriteBound &bound);
  void add_bound(const std::string &fn, const LogWriteBound &bound);

protected:
  static std::unique_ptr<BoundRegistry> instance;
  std::unordered_map<std::string, LogWriteBound> bounds_;
};

void verify_num_logwrite_bound(LogOpCounter *verifier,
                               std::shared_ptr<ExecutionState> init_state,
                               int bound);

void verify_num_logwrite_bound(LogOpCounter *verifier,
                               std::shared_ptr<ExecutionState> init_state,
                               const std::vector<RegValue> &params,
                               const LogWriteBound &bound);

void init_execution_state(std::shared_ptr<ExecutionState> &s);
