#pragma once

#include <stack>
#include <string>
#include <unordered_map>
#include <variant>

#include "llvm-helpers.h"
#include "llvm-incl.h"
#include "symbolic-expr.h"
#include "utils.h"
#include "z3-gen.h"

class Pointee;
class Buffer;

class IRDataBase {
public:
  IRDataBase();

  void load_ir_file(const std::string &ir_filename);

  llvm::Function *get_fn_by_name(const std::string &func_name) const;
  llvm::Function *get_fn_by_prefix(const std::string &prefix) const;

  llvm::LLVMContext &get_ctx() const;

protected:
  llvm::LLVMContext ctx_;
  llvm::SMDiagnostic err_;

  std::unordered_map<std::string, std::unique_ptr<llvm::Module>> modules_;
};

std::pair<std::string, int> get_inst_loc(const llvm::Instruction &inst);

struct SymPointer {
  std::string pointer_base;
  llvm::Type *llvm_type = nullptr;

  bool is_shm_ptr = false;
  bool is_log_ptr = false;

  Symbolic::ExprPtr offset;

  SymPointer() {}

  SymPointer(const std::string &base);
  SymPointer(const std::string &base, llvm::Type *t, Symbolic::ExprPtr off);
};

struct RegValue {
  std::variant<Symbolic::ExprPtr, SymPointer> content;

  bool is_val() const;
  bool is_ptr() const;

  Symbolic::ExprPtr &get_val();
  SymPointer &get_ptr();

  const SymPointer &get_ptr() const;
  const Symbolic::ExprPtr &get_val() const;
};

struct ExecError {
  std::string msg;

  std::string exception_file;
  int exception_line;

  std::string file_name;
  int line_number;

  ExecError();
  ExecError(const std::string &msg);
  ExecError(const llvm::Instruction &inst, const std::string &msg);
};

struct ExecutionState {
  llvm::BasicBlock::iterator inst_iter;
  llvm::BasicBlock::iterator bb_end;

  llvm::BasicBlock *prev_bb = nullptr;

  std::vector<Symbolic::ExprPtr> pre_cond_list;

  std::unordered_map<std::string, RegValue> registers;
  std::unordered_map<std::string, std::shared_ptr<Pointee>> objects;

  std::string shm_mem_name;
  std::shared_ptr<Buffer> shm_mem;

  std::string log_mem_name;
  std::shared_ptr<Buffer> log_mem;

  NameFactory &name_gen;
  RegValue ret_val;

  std::vector<std::shared_ptr<ExecutionState>> crashed_states;

  bool finished_execution = false;
  bool have_new_cond = false;

  bool is_assert_fail = false;
  std::string fail_msg;

  enum class ValidT {
    VALID,
    INVALID,
    UNKNOWN,
  };

  ValidT valid = ValidT::UNKNOWN;

  ExecutionState(NameFactory &name_gen);
  ExecutionState(NameFactory &name_gen, llvm::Function *f);
  ExecutionState(const ExecutionState &s);

  std::shared_ptr<ExecutionState> copy_self() const {
    auto c = std::make_shared<ExecutionState>(*this);
    c->shm_mem = std::dynamic_pointer_cast<Buffer>(c->objects[shm_mem_name]);
    c->log_mem = std::dynamic_pointer_cast<Buffer>(c->objects[log_mem_name]);
    // std::cout << "after copy: " << std::endl;
    // for (auto &kv : c->objects) {
    //     std::cout << kv.first << " : " << kv.second.get() << std::endl;
    // }
    return c;
  }

  RegValue get_reg_val(const llvm::Value &value) const;
  RegValue get_reg_val(const std::string &reg_name) const;
  void set_reg_val(const std::string &reg_name, const RegValue &val);
  void jump_to_bb(llvm::BasicBlock *bb);
  std::shared_ptr<Pointee> find_pointee(const std::string &name) const;
  void add_pointee(std::shared_ptr<Pointee> pointee);
  void add_crash_point();

  void init_with_fn(llvm::Function *f);
  void init_shm_log();
  void add_pre_cond(Symbolic::ExprPtr c);
  Symbolic::ExprPtr get_pre_cond() const;

  // valid means reachable
  bool is_valid();

  // TODO: add states for tracking function contexts for caller
  // we need to emulate a function call stack here
  struct Context {
    // register values
    std::unordered_map<std::string, RegValue> registers;

    // return address
    llvm::BasicBlock::iterator inst_iter;
    llvm::BasicBlock::iterator bb_end;

    // return reg
    std::string ret_val_reg;

    std::string function_name;
  };
  std::stack<Context> call_stack;
};

struct VerificationResult {
  bool have_ce = true;

  VerificationResult(bool found_ce);
};

using StatePtrList = std::vector<std::shared_ptr<ExecutionState>>;

class CrashVerifier {
public:
  CrashVerifier(std::unique_ptr<IRDataBase> db);

  bool verify_crash_safe(const std::string &fn, const std::string &recover_fn,
                         std::shared_ptr<ExecutionState> init_state,
                         int num_worker = 1);

  StatePtrList run(std::shared_ptr<ExecutionState> init_state,
                   int num_worker = 1, bool skip_pre_cond_check = false);
  StatePtrList single_step(std::shared_ptr<ExecutionState> state);

  IRDataBase *irdb() { return irdb_.get(); }

protected:
  std::unique_ptr<IRDataBase> irdb_;
};

class LogOpCounter {
public:
  LogOpCounter(std::unique_ptr<IRDataBase> db);

  StatePtrList run(std::shared_ptr<ExecutionState> init_state,
                   int num_worker = 1);
  StatePtrList single_step(std::shared_ptr<ExecutionState> state);

  IRDataBase *irdb() { return irdb_.get(); }

protected:
  std::unique_ptr<IRDataBase> irdb_;
};
