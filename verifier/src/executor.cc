#include <atomic>
#include <deque>
#include <mutex>
#include <queue>
#include <thread>

#include "abstract-functions.h"
#include "data-structures.h"
#include "executor.h"
#include "llvm-helpers.h"
#include "logwrite_bound.h"
#include "utils.h"

std::pair<std::string, int> get_inst_loc(const llvm::Instruction &inst) {
  std::string file_name = "";
  int line_number = -1;
  if (llvm::DILocation *Loc = inst.getDebugLoc()) {
    unsigned ln = Loc->getLine();
    auto fn = Loc->getFilename().str();
    auto dir = Loc->getDirectory().str();
    file_name = dir + "/" + fn;
    line_number = ln;
  }
  return {file_name, line_number};
}

IRDataBase::IRDataBase() {}

void IRDataBase::load_ir_file(const std::string &ir_filename) {
  auto module = llvm::parseIRFile(ir_filename, err_, ctx_);
  if (module == nullptr) {
    std::cerr << err_.getMessage().str() << std::endl;
    assert(false && "parseIRFile failed");
  }

  assert(modules_.find(ir_filename) == modules_.end());

  modules_.insert({ir_filename, std::move(module)});
}

llvm::Function *IRDataBase::get_fn_by_name(const std::string &func_name) const {
  for (auto &kv : modules_) {
    auto &m = kv.second;
    for (auto iter = m->begin(); iter != m->end(); iter++) {
      if (iter->isDeclaration()) {
        continue;
      }
      auto fn = iter->getName().str();
      if (fn == func_name) {
        return &*iter;
      }
      auto fn_demangled = demangle_cpp_name(fn);
      if (fn_demangled == func_name) {
        return &*iter;
      }
    }
  }
  return nullptr;
}

llvm::Function *IRDataBase::get_fn_by_prefix(const std::string &prefix) const {
  for (auto &kv : modules_) {
    auto &m = kv.second;
    for (auto iter = m->begin(); iter != m->end(); iter++) {
      if (iter->isDeclaration()) {
        continue;
      }
      auto fn = iter->getName().str();
      if (is_prefix(fn, prefix)) {
        return &*iter;
      }
      auto fn_demangled = demangle_cpp_name(fn);
      if (is_prefix(fn_demangled, prefix)) {
        return &*iter;
      }
    }
  }
  return nullptr;
}

SymPointer::SymPointer(const std::string &base)
    : pointer_base(base), offset(mk_concrete_bv(64, 0)) {}

SymPointer::SymPointer(const std::string &base, llvm::Type *t,
                       Symbolic::ExprPtr off)
    : pointer_base(base), llvm_type(t), offset(off) {}

bool RegValue::is_val() const {
  return std::holds_alternative<Symbolic::ExprPtr>(content);
}

bool RegValue::is_ptr() const {
  return std::holds_alternative<SymPointer>(content);
}

SymPointer &RegValue::get_ptr() { return std::get<SymPointer>(content); }

Symbolic::ExprPtr &RegValue::get_val() {
  return std::get<Symbolic::ExprPtr>(content);
}

const SymPointer &RegValue::get_ptr() const {
  return std::get<SymPointer>(content);
}

const Symbolic::ExprPtr &RegValue::get_val() const {
  return std::get<Symbolic::ExprPtr>(content);
}

ExecError::ExecError() : file_name(""), line_number(-1) {}

ExecError::ExecError(const std::string &s)
    : msg(s), file_name(""), line_number(-1) {}

ExecError::ExecError(const llvm::Instruction &inst, const std::string &s)
    : msg(s) {
  if (llvm::DILocation *Loc =
          inst.getDebugLoc()) { // Here I is an LLVM instruction
    unsigned ln = Loc->getLine();
    auto fn = Loc->getFilename().str();
    auto dir = Loc->getDirectory().str();
    file_name = dir + "/" + fn;
    line_number = ln;
  } else {
    file_name = "";
    line_number = -1;
  }
}

ExecutionState::ExecutionState(NameFactory &gen)
    : name_gen(gen), shm_mem(nullptr), log_mem(nullptr) {
  init_shm_log();
}

ExecutionState::ExecutionState(NameFactory &gen, llvm::Function *f)
    : name_gen(gen) {
  init_with_fn(f);
  init_shm_log();
}

void ExecutionState::init_shm_log() {
  shm_mem = std::make_shared<Buffer>(name_gen("shm_mem"), 0, 8);
  log_mem = std::make_shared<ConcreteCacheBuffer>(name_gen("log_mem"));
  shm_mem_name = shm_mem->name;
  log_mem_name = log_mem->name;
  add_pointee(shm_mem);
  add_pointee(log_mem);
}

ExecutionState::ExecutionState(const ExecutionState &s) : name_gen(s.name_gen) {
  inst_iter = s.inst_iter;
  bb_end = s.bb_end;

  pre_cond_list = s.pre_cond_list;
  have_new_cond = s.have_new_cond;
  finished_execution = s.finished_execution;
  valid = s.valid;

  registers.clear();
  for (auto &kv : s.registers) {
    registers.insert({kv.first, kv.second});
  }

  objects.clear();
  for (auto &kv : s.objects) {
    objects.insert({kv.first, kv.second->copy_self()});
  }

  shm_mem_name = s.shm_mem_name;
  log_mem_name = s.log_mem_name;

  for (auto &cs : s.crashed_states) {
    crashed_states.push_back(cs);
  }

  call_stack = s.call_stack;
}

RegValue ExecutionState::get_reg_val(const llvm::Value &value) const {
  auto val_name = get_name(value);
  auto t = value.getType();
  if (t->isPointerTy() && t->getPointerElementType()->isFunctionTy()) {
    throw "TODO: get func_name";
  }

  if (val_name == "undef") {
    auto bv64_t = std::make_shared<Symbolic::BitVecType>(64);
    if (t->isPointerTy()) {
      SymPointer ptr{"undef", nullptr,
                     mk_expr_ptr(SymbolicVar, bv64_t, name_gen("undef"))};
      return RegValue{ptr};
    } else if (t->isIntegerTy()) {
      auto size = t->getIntegerBitWidth();
      return RegValue{mk_expr_ptr(SymbolicVar, bv64_t, name_gen("undef"))};
    }
  }

  if (const llvm::ConstantInt *CI =
          llvm::dyn_cast<const llvm::ConstantInt>(&value)) {
    // constant integer
    if (CI->getBitWidth() <= 64) {
      return RegValue{
          mk_expr_ptr(ConcreteBv, CI->getBitWidth(), CI->getSExtValue())};
    } else {
      assert(false && "integer too large");
    }
  }

  return get_reg_val(val_name);
}

RegValue ExecutionState::get_reg_val(const std::string &reg_name) const {
  if (registers.find(reg_name) != registers.end()) {
    return registers.find(reg_name)->second;
  }
  if (reg_name == "null") {
    SymPointer ptr;
    ptr.pointer_base = "";
    ptr.offset = mk_expr_ptr(ConcreteBv, 64, 0);
    return RegValue{ptr};
  } else if (reg_name == "true") {
    return RegValue{mk_expr_ptr(ConcreteBv, 1, 1)};
  } else if (reg_name == "false") {
    return RegValue{mk_expr_ptr(ConcreteBv, 1, 0)};
  }

  throw ExecError("unknown register");
}
void ExecutionState::set_reg_val(const std::string &reg_name,
                                 const RegValue &val) {
  registers[reg_name] = val;
}

std::shared_ptr<Pointee>
ExecutionState::find_pointee(const std::string &name) const {
  if (objects.find(name) != objects.end()) {
    return objects.find(name)->second;
  }
  assert(false && "Could not find Pointee");
}

void ExecutionState::add_pointee(std::shared_ptr<Pointee> pointee) {
  assert(objects.find(pointee->name) == objects.end());
  objects.insert({pointee->name, pointee});
}

void ExecutionState::add_crash_point() {
  auto cs = this->copy_self();
  cs->crashed_states.clear();
  this->crashed_states.push_back(cs);
}

void ExecutionState::jump_to_bb(llvm::BasicBlock *bb) {
  inst_iter = bb->begin();
  bb_end = bb->end();
  prev_bb = inst_iter->getParent();
}

void ExecutionState::init_with_fn(llvm::Function *f) {
  auto &bb = f->getEntryBlock();
  inst_iter = bb.begin();
  bb_end = bb.end();
}

void ExecutionState::add_pre_cond(Symbolic::ExprPtr c) {
  valid = ValidT::UNKNOWN;
  have_new_cond = true;
  pre_cond_list.push_back(c);
}

Symbolic::ExprPtr ExecutionState::get_pre_cond() const {
  if (pre_cond_list.size() == 0) {
    // no pre cond return "true" (1)
    return mk_concrete_bv(1, 1);
  }

  Symbolic::ExprPtr result = pre_cond_list[0];
  for (int i = 1; i < pre_cond_list.size(); i++) {
    result = mk_expr_ptr(AndExpr, {result, pre_cond_list[i]});
  }
  return result;
}

bool ExecutionState::is_valid() {
  if (valid == ValidT::UNKNOWN) {
    auto pre_cond = get_pre_cond();
    Symbolic::Z3Context ctx;
    z3::solver sol(ctx.ctx);
    sol.add(gen_z3_expr(ctx, pre_cond).get_bool());
    if (sol.check() == z3::unsat) {
      valid = ValidT::INVALID;
    } else {
      valid = ValidT::VALID;
    }
  }
  return valid == ValidT::VALID;
}

VerificationResult::VerificationResult(bool found_ce) : have_ce(found_ce) {}

class SymExecVisitor : public llvm::InstVisitor<SymExecVisitor> {
public:
  std::shared_ptr<ExecutionState> state;
  std::vector<std::shared_ptr<ExecutionState>> &nexts;
  bool count_log_write = false;

  const IRDataBase &irdb;

  SymExecVisitor(std::shared_ptr<ExecutionState> s,
                 std::vector<std::shared_ptr<ExecutionState>> &r,
                 const IRDataBase &db)
      : state(s), nexts(r), irdb(db) {}

  void visitInstruction(const llvm::Instruction &inst) {
    llvm::errs() << "OOPS: ";
    inst.print(llvm::errs());
    llvm::errs() << "\n";
    assert(false && "unknow instruction");
  }

  void visitReturnInst(const llvm::ReturnInst &inst) {
    // TODO: support funciton return;
    RegValue ret_val;
    if (inst.getReturnValue() != nullptr) {
      ret_val = state->get_reg_val(*inst.getReturnValue());
    }
    if (state->call_stack.empty()) {
      state->finished_execution = true;
      state->ret_val = ret_val;
      nexts.push_back(state);
    } else {
      // restore the last context from "call_stack"
      auto last_ctx = state->call_stack.top();
      state->call_stack.pop();
      // for (int i = 0; i < state->call_stack.size(); i++) {
      //     std::cout << "  ";
      // }
      // std::cout << "Returning from: " << last_ctx.function_name << std::endl;
      state->registers = last_ctx.registers;
      state->inst_iter = last_ctx.inst_iter;
      state->bb_end = last_ctx.bb_end;
      state->inst_iter++;
      if (last_ctx.ret_val_reg != "" && inst.getReturnValue() != nullptr) {
        state->set_reg_val(last_ctx.ret_val_reg, ret_val);
      } else {
        assert(inst.getReturnValue() == nullptr);
      }
      nexts.push_back(state);
    }
  }

  void visitBranchInst(const llvm::BranchInst &inst) {
    if (inst.isConditional()) {
      auto cond_reg = get_name(*inst.getCondition());
      assert(state->registers.find(cond_reg) != state->registers.end());
      auto cond_val = state->registers[cond_reg];
      assert(cond_val.is_val());
      auto t_target_bb = inst.getSuccessor(0);
      auto f_target_bb = inst.getSuccessor(1);

      // first try to short circuit this
      // Symbolic::Z3Context ctx;
      // std::cout << Symbolic::gen_z3_expr(ctx,
      // cond_val.get_val()).get_expr().simplify() << std::endl;
      if (cond_val.get_val()->simplify()->is_symbolic()) {
        // now create two copies of the ExecContext
        auto t_ctx = state->copy_self();
        t_ctx->jump_to_bb(t_target_bb);
        t_ctx->add_pre_cond(cond_val.get_val());
        nexts.push_back(t_ctx);

        auto f_ctx = state->copy_self();
        f_ctx->jump_to_bb(f_target_bb);
        f_ctx->add_pre_cond(mk_expr_ptr(LNotExpr, cond_val.get_val()));
        nexts.push_back(f_ctx);
      } else {
        auto cond = cond_val.get_val()->simplify();
        auto bool_val =
            std::dynamic_pointer_cast<Symbolic::ConcreteBv>(cond)->get_val();
        if (bool_val) {
          state->jump_to_bb(t_target_bb);
          nexts.push_back(state);
        } else {
          state->jump_to_bb(f_target_bb);
          nexts.push_back(state);
        }
      }
    } else {
      auto target_bb = inst.getSuccessor(0);
      state->jump_to_bb(target_bb);
      nexts.push_back(state);
    }
  }

  void visitSwitchInst(const llvm::SwitchInst &inst) {
    auto cond_reg_val = state->registers[get_name(*inst.getCondition())];
    assert(cond_reg_val.is_val());
    auto cond_val = cond_reg_val.get_val();
    auto bw = cond_val->type->get_bv_width();

    Symbolic::ExprPtr default_cond = nullptr;
    for (auto i = inst.case_begin(); i != inst.case_end(); i++) {
      auto c = *i;
      auto val = c.getCaseValue()->getSExtValue();
      auto target_bb = c.getCaseSuccessor();
      auto eq =
          mk_expr_ptr(EqExpr, {cond_val, mk_expr_ptr(ConcreteBv, bw, val)});
      auto neq = mk_expr_ptr(LNotExpr, eq);

      if (default_cond == nullptr) {
        default_cond = neq;
      } else {
        default_cond = mk_expr_ptr(LAndExpr, {default_cond, neq});
      }
      auto taken_ctx = state->copy_self();
      taken_ctx->jump_to_bb(const_cast<llvm::BasicBlock *>(target_bb));
      taken_ctx->add_pre_cond(eq);
      nexts.push_back(taken_ctx);
    }
    auto default_bb = inst.getDefaultDest();
    auto default_ctx = state->copy_self();
    default_ctx->jump_to_bb(default_bb);
    default_ctx->add_pre_cond(default_cond);
    nexts.push_back(default_ctx);
  }

  void visitICmpInst(const llvm::ICmpInst &inst) {
    auto dst_reg = get_name(inst);
    using P = llvm::CmpInst::Predicate;
    auto predicate = inst.getPredicate();
    auto op_val1 = state->get_reg_val(*inst.getOperand(0));
    auto op_val2 = state->get_reg_val(*inst.getOperand(1));
    Symbolic::ExprPtr op1 = nullptr;
    Symbolic::ExprPtr op2 = nullptr;
    if (op_val1.is_ptr()) {
      // pointer comparasion, only support eq or ne null
      auto ptr1 = op_val1.get_ptr();
      auto ptr2 = op_val2.get_ptr();
      // assert(predicate == P::ICMP_EQ || predicate == P::ICMP_NE);
      bool same_buffer = (ptr1.pointer_base == ptr2.pointer_base);
      Symbolic::ExprPtr ptr_eq = nullptr;

      if (same_buffer) {
        op1 = ptr1.offset;
        op2 = ptr2.offset;
      } else if (predicate == P::ICMP_EQ) {
        state->set_reg_val(dst_reg, RegValue{mk_concrete_bv(1, 0)});
        state->inst_iter++;
        nexts.push_back(state);
        return;
      } else if (predicate == P::ICMP_NE) {
        state->set_reg_val(dst_reg, RegValue{mk_concrete_bv(1, 1)});
        state->inst_iter++;
        nexts.push_back(state);
        return;
      } else {
        assert(false && "comparing different pointers");
      }
    } else {
      op1 = state->get_reg_val(*inst.getOperand(0)).get_val();
      op2 = state->get_reg_val(*inst.getOperand(1)).get_val();
    }
    Symbolic::ExprPtr val = nullptr;
#define PRED_CASE(LLVM_PRED, EXPR_T)                                           \
  case LLVM_PRED:                                                              \
    val = mk_expr_ptr(EXPR_T, {op1, op2});                                     \
    break
    switch (predicate) {
      PRED_CASE(P::ICMP_EQ, EqExpr);
      PRED_CASE(P::ICMP_NE, NeqExpr);
      PRED_CASE(P::ICMP_SLE, LeExpr);
      PRED_CASE(P::ICMP_SLT, LtExpr);
      PRED_CASE(P::ICMP_SGE, GeExpr);
      PRED_CASE(P::ICMP_SGT, GtExpr);
      PRED_CASE(P::ICMP_ULE, UleExpr);
      PRED_CASE(P::ICMP_ULT, UltExpr);
      PRED_CASE(P::ICMP_UGE, UgeExpr);
      PRED_CASE(P::ICMP_UGT, UgtExpr);
    default:
      assert(false && "unsupported icmp");
    }
    auto n = state->copy_self();
    n->set_reg_val(dst_reg, RegValue{val});
    n->inst_iter++;
    nexts.push_back(n);
  }

  void visitAllocaInst(const llvm::AllocaInst &inst) {
    auto dst = get_name(inst);
    const llvm::Value *val = inst.getArraySize();
    int64_t size = get_int_val(val);
    assert(size > 0);

    auto type = inst.getAllocatedType();
    auto type_size = get_type_size(inst.getModule(), type);
    assert(type_size > 0);

    auto buf_name = state->name_gen("alloca" + dst);
    std::shared_ptr<Pointee> buf = nullptr;
    if (type->isPointerTy()) {
      buf = std::make_shared<PointerStore>(buf_name);
    } else {
      buf = std::make_shared<ConcreteCacheBuffer>(buf_name, type_size);
    }
    state->objects.insert({buf_name, std::dynamic_pointer_cast<Pointee>(buf)});

    SymPointer ptr;
    ptr.pointer_base = buf_name;
    ptr.offset = mk_concrete_bv(64, 0);
    state->set_reg_val(dst, RegValue{ptr});
    state->inst_iter++;
    nexts.push_back(state);
  }

  void visitLoadInst(const llvm::LoadInst &inst) {
    std::string dst_reg = get_name(inst);
    auto ptr_reg = get_name(*inst.getOperand(0));
    auto ptr = state->get_reg_val(*inst.getOperand(0)).get_ptr();
    auto base = ptr.pointer_base;

    auto ptr_type = inst.getPointerOperand()->getType();
    auto data_type = ptr_type->getPointerElementType();
    uint64_t size = get_type_size(inst.getModule(), data_type);

    // find the buffer
    std::shared_ptr<Pointee> pointee = state->find_pointee(base);
    if (pointee == nullptr) {
      throw ExecError{"could not find buffer to load from"};
    }
    RegValue val;
    if (pointee->type() == PointeeType::PointerStore) {
      auto off = ptr.offset->simplify();
      auto p_store = std::dynamic_pointer_cast<PointerStore>(pointee);
      if (!off->is_symbolic()) {
        assert(
            std::dynamic_pointer_cast<Symbolic::ConcreteBv>(off)->get_val() ==
            0);
        val = RegValue{p_store->load_ptr()};
      } else {
        auto multi_ptr = p_store->load_ptr(off);
        auto no_match = mk_concrete_bv(1, 1);
        for (auto &e : multi_ptr) {
          auto n = state->copy_self();
          n->add_pre_cond(e.pre_cond);
          n->set_reg_val(dst_reg, RegValue{e.ptr});
          n->inst_iter++;
          nexts.push_back(n);

          no_match = mk_expr_ptr(AndExpr,
                                 {no_match, mk_expr_ptr(NotExpr, e.pre_cond)});
        }
        state->add_pre_cond(no_match);
        /*
        Symbolic::Z3Context ctx;
        z3::solver sol(ctx.ctx);
        sol.add(gen_z3_expr(ctx, state->get_pre_cond()).get_bool());
        assert(sol.check() == z3::unsat);
        */
        // state->is_assert_fail = true;
        // state->fail_msg = "loading from pointer store: no match found";
        val = RegValue{mk_bv_var(64, state->name_gen("rand"))};
      }
    } else {
      val = pointee->load(ptr.offset, size);
      /*
      if (pointee == state->shm_mem || pointee == state->log_mem) {
        if (pointee == state->shm_mem) {
          std::cout << "Shm load" << std::endl;
        } else {
          std::cout << "Log load" << std::endl;
        }
        std::cout << "Load offset: ";
        Symbolic::print_expr_z3(ptr.offset, std::cout);
        std::cout << std::endl << "Store val: ";
        Symbolic::print_expr_z3(val.get_val(), std::cout);
        std::cout << std::endl;
      }
      */
    }
    state->set_reg_val(dst_reg, val);
    state->inst_iter++;
    nexts.push_back(state);
  }

  void visitStoreInst(const llvm::StoreInst &inst) {
    auto ptr_reg = get_name(*inst.getOperand(1));
    auto ptr = state->get_reg_val(*inst.getOperand(1)).get_ptr();
    auto base = ptr.pointer_base;
    auto val = state->get_reg_val(*inst.getOperand(0));

    // find the buffer
    std::shared_ptr<Pointee> pointee = state->find_pointee(base);
    if (pointee == nullptr) {
      throw ExecError{"could not find buffer to load from"};
    }
    if (pointee->name == state->shm_mem_name ||
        pointee->name == state->log_mem_name) {
      auto cnt = state->find_pointee(log_write_cnt_name)
                     ->load(mk_concrete_bv(64, 0), 8)
                     .get_val();
      auto new_cnt = mk_expr_ptr(AddExpr, {cnt, mk_concrete_bv(64, 1)});
      state->find_pointee(log_write_cnt_name)
          ->store(mk_concrete_bv(64, 0), RegValue{new_cnt});
      // assert(false && "Error: writing to log memory or shared memory
      // directly!");
    }
    if (val.is_ptr()) {
      assert(pointee->type() == PointeeType::PointerStore);
      auto p_store = std::dynamic_pointer_cast<PointerStore>(pointee);
      p_store->store_ptr(val.get_ptr());
    } else {
      if (pointee == state->shm_mem || pointee == state->log_mem) {
        assert(false);
        // std::cout << "store to: " << base << std::endl;
        // std::cout << "adding to crash state" << std::endl;
        state->add_crash_point();
        /*
        if (pointee == state->log_mem) {
          if (pointee == state->shm_mem) {
            std::cout << "Shm store" << std::endl;
          } else {
            std::cout << "Log store" << std::endl;
          }
          std::cout << "Store offset: " <<
        ptr.offset->simplify()->is_symbolic();
          Symbolic::print_expr_z3(ptr.offset, std::cout);
          // std::cout << std::endl << "Store val: ";
          // Symbolic::print_expr_z3(val.get_val(), std::cout);
          std::cout << std::endl;
          if (ptr.offset->simplify()->is_symbolic()) {
            print_expr(ptr.offset->simplify(), std::cout);
            std::cout << std::endl;
            assert(false);
          }
        }
        */
      }
      if (pointee->type() == PointeeType::Buffer) {
        auto buf = std::dynamic_pointer_cast<Buffer>(pointee);
        if (buf->cell_size > 1) {
          // verify alignment
          auto mod = mk_expr_ptr(
              UModExpr, {ptr.offset, mk_concrete_bv(64, buf->cell_size)});
          auto eq0 = mk_expr_ptr(EqExpr, {mod, mk_concrete_bv(64, 0)});
          assert(val.get_val()->type->get_bv_width() % (buf->cell_size * 8) ==
                 0);
        }
      }
      pointee->store(ptr.offset, val);
    }
    state->inst_iter++;
    nexts.push_back(state);
  }

  void visitGetElementPtrInst(const llvm::GetElementPtrInst &inst) {
    auto base_ptr = state->get_reg_val(*inst.getOperand(0));
    std::vector<Symbolic::ExprPtr> offsets_sym;
    std::vector<int> offsets_int;
    std::vector<Symbolic::ExprPtr> offsets;
    for (int i = 1; i < inst.getNumOperands(); i++) {
      // need to extend offsets to 64-bit integer
      auto v = inst.getOperand(i);
      Symbolic::ExprPtr off = nullptr;
      if (const llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(v)) {
        offsets_int.push_back(CI->getSExtValue());
        offsets_sym.push_back(nullptr);
        off = mk_expr_ptr(ConcreteBv, 64, CI->getSExtValue());
      } else {
        offsets_int.push_back(-1);
        off = state->get_reg_val(*inst.getOperand(i)).get_val();
        offsets_sym.push_back(off);
      }
      assert(off != nullptr);
      offsets.push_back(off);
    }
    auto type = inst.getOperand(0)->getType();
    Symbolic::ExprPtr off_val = mk_expr_ptr(ConcreteBv, 64, 0);
    for (int i = 0; i < offsets.size(); i++) {
      if (type->isPointerTy()) {
        auto size =
            get_type_size(inst.getModule(), type->getPointerElementType());
        auto off = mk_expr_ptr(MulExpr,
                               {offsets[i], mk_expr_ptr(ConcreteBv, 64, size)});
        off_val = mk_expr_ptr(AddExpr, {off_val, off});
        type = type->getPointerElementType();
      } else if (type->isStructTy()) {
        auto dl = std::make_shared<llvm::DataLayout>(inst.getModule());
        auto sl = dl->getStructLayout(static_cast<llvm::StructType *>(type));
        assert(offsets_int[i] >= 0);
        auto off = sl->getElementOffset(offsets_int[i]);
        off_val =
            mk_expr_ptr(AddExpr, {off_val, mk_expr_ptr(ConcreteBv, 64, off)});
        type = type->getStructElementType(offsets_int[i]);
      } else if (type->isArrayTy()) {
        auto size =
            get_type_size(inst.getModule(), type->getArrayElementType());
        auto off = mk_expr_ptr(MulExpr,
                               {offsets[i], mk_expr_ptr(ConcreteBv, 64, size)});
        off_val = mk_expr_ptr(AddExpr, {off_val, off});
        type = type->getArrayElementType();
      }
      // now check if the pointer falls
    }
    std::string dst_reg = get_name(inst);
    SymPointer ptr = base_ptr.get_ptr();
    // std::cout << ptr.offset.get() << std::endl;
    ptr.offset = mk_expr_ptr(AddExpr, {ptr.offset, off_val});
    ptr.offset = ptr.offset->simplify();
    auto ptr_base_obj = state->find_pointee(ptr.pointer_base);
    if (ptr_base_obj->type() == PointeeType::Object) {
      if (!ptr.offset->is_symbolic()) {
        // TODO: try find the actual object
        AbstractObject::Region r;
        auto obj = std::dynamic_pointer_cast<AbstractObject>(ptr_base_obj);
        auto offset_val =
            std::dynamic_pointer_cast<Symbolic::ConcreteBv>(ptr.offset)
                ->get_val();
        int not_found = obj->find_region(offset_val, r);
        if (!not_found) {
          ptr = r.ptr;
        }
      } else {
        // accessing object with symbolic offset
        auto obj = std::dynamic_pointer_cast<AbstractObject>(ptr_base_obj);
        auto regions = obj->find_region(ptr.offset);

        auto not_in_any_range = mk_concrete_bv(1, 1);
        for (auto &e : regions) {
          auto n = state->copy_self();
          n->set_reg_val(dst_reg, RegValue{e.region.ptr});
          n->inst_iter++;
          n->add_pre_cond(e.pre_cond);
          nexts.push_back(n);
          not_in_any_range = mk_expr_ptr(
              AndExpr, {not_in_any_range, mk_expr_ptr(NotExpr, e.pre_cond)});
        }
        state->add_pre_cond(not_in_any_range);
      }
    }

    state->set_reg_val(dst_reg, RegValue{ptr});
    state->inst_iter++;
    nexts.push_back(state);
  }

  void visitPHINode(const llvm::PHINode &inst) {
    auto dst = get_name(inst);
    bool found = false;
    for (auto i = 0; i < inst.getNumIncomingValues(); i++) {
      auto bb = inst.getIncomingBlock(i);
      if (get_name(*state->prev_bb) == get_name(*bb)) {
        auto val = state->get_reg_val(*inst.getIncomingValue(i));
        state->set_reg_val(dst, val);
        state->inst_iter++;
        nexts.push_back(state);
        found = true;
        break;
      }
    }
    if (!found) {
      assert(false && "from unknown basic block");
    }
  }

  void visitTruncInst(const llvm::TruncInst &inst) {
    std::string dst_reg = get_name(inst);
    auto val = state->get_reg_val(*inst.getOperand(0));
    assert(val.is_val());
    auto dst_type = inst.getDestTy();
    int target_size =
        llvm::dyn_cast<llvm::IntegerType>(dst_type)->getBitWidth();
    state->set_reg_val(dst_reg, RegValue{mk_expr_ptr(ExtractExpr, val.get_val(),
                                                     0, target_size)});
    state->inst_iter++;
    nexts.push_back(state);
  }

  void visitZExtInst(const llvm::ZExtInst &inst) {
    std::string dst_reg = get_name(inst);
    auto val = state->get_reg_val(*inst.getOperand(0));
    auto dst_type = inst.getDestTy();
    assert(dst_type->isIntegerTy());
    int target_size =
        llvm::dyn_cast<llvm::IntegerType>(dst_type)->getBitWidth();
    auto new_val = mk_expr_ptr(UExtExpr, val.get_val(), target_size);
    state->set_reg_val(dst_reg, RegValue{new_val});
    state->inst_iter++;
    nexts.push_back(state);
  }

  void visitSExtInst(const llvm::SExtInst &inst) {
    std::string dst_reg = get_name(inst);
    auto val = state->get_reg_val(*inst.getOperand(0));
    auto dst_type = inst.getDestTy();
    assert(dst_type->isIntegerTy());
    int target_size =
        llvm::dyn_cast<llvm::IntegerType>(dst_type)->getBitWidth();
    auto new_val = mk_expr_ptr(SExtExpr, val.get_val(), target_size);
    state->set_reg_val(dst_reg, RegValue{new_val});
    state->inst_iter++;
    nexts.push_back(state);
  }

  void visitPtrToIntInst(const llvm::PtrToIntInst &inst) {
    std::string dst_reg = get_name(inst);
    auto ptr = state->get_reg_val(*inst.getOperand(0)).get_ptr();
    auto base = ptr.pointer_base;
    std::shared_ptr<Pointee> pointee = state->find_pointee(base);
    if (pointee->name != state->shm_mem_name) {
      // we only allow ptr to int on shared memory (and will only used it to
      // compute offset)
      inst.print(llvm::errs());
      llvm::errs() << "\n";
      assert(false && "not implemented");
    }
    state->set_reg_val(dst_reg, RegValue{ptr});
    state->inst_iter++;
    nexts.push_back(state);
    // std::string dst_reg = get_name(inst);
    // auto ptr = state->get_reg_val(*inst.getOperand(0)).get_ptr();

    // Symbolic::ExprPtr base = nullptr;
    // if (state->pointer_base.find(ptr.pointer_base) !=
    // state->pointer_base.end()) {
    //     base = state->pointer_base.find(ptr.pointer_base)->second;
    // } else {
    //     auto vn = state->name_gen->gen(ptr.pointer_base + "!base");
    //     auto bv64 = std::make_shared<Symbolic::BitVecType>(64);
    //     base = mk_expr_ptr(SymbolicVar, bv64, vn);
    //     state->pointer_base[ptr.pointer_base] = base;
    // }

    // auto val = mk_expr_ptr(AddExpr, {base, ptr.offset});

    // state->set_reg_val(dst_reg, RegValue{val});
    // state->inst_iter_++;
    // nexts.push_back(state);
  }

  void visitIntToPtrInst(const llvm::IntToPtrInst &inst) {
    inst.print(llvm::errs());
    llvm::errs() << "\n";
    assert(false && "not implemented");
  }

  void visitBitCastInst(const llvm::BitCastInst &inst) {
    auto src_type = inst.getSrcTy();
    auto dst_type = inst.getDestTy();
    assert(src_type->isPointerTy() && dst_type->isPointerTy());
    src_type = src_type->getPointerElementType();
    dst_type = dst_type->getPointerElementType();

    std::string dst_reg = get_name(inst);
    auto val = state->get_reg_val(*inst.getOperand(0));
    state->set_reg_val(dst_reg, val);
    state->inst_iter++;
    nexts.push_back(state);
  }

  void visitBinaryOperator(const llvm::BinaryOperator &inst) {
    std::string dst_reg = get_name(inst);
    auto op1 = state->get_reg_val(*inst.getOperand(0));
    auto op2 = state->get_reg_val(*inst.getOperand(1));
    std::string opstring = inst.getOpcodeName();
    using namespace Symbolic;
    using BinOpF = std::function<ExprPtr(ExprPtr, ExprPtr)>;
    bool is_bv = true;
    if (op1.is_ptr()) {
      // std::cout << "Got pointer in binary operator" << std::endl;
      // offset calculation from shm pointers
      // here we just return a fresh bv
      assert(opstring == "sub");
      assert(op2.is_ptr());
      auto ptr1 = op1.get_ptr();
      auto ptr2 = op2.get_ptr();
      assert(ptr1.pointer_base == state->shm_mem_name);
      assert(ptr2.pointer_base == state->shm_mem_name);
      state->set_reg_val(dst_reg,
                         RegValue{mk_bv_var(64, state->name_gen("offset"))});
      state->inst_iter++;
      nexts.push_back(state);
      return;
    }
    if (op1.get_val()->type->get_bv_width() == 1) {
      is_bv = false;
    }
    // std::cout << "logical??: " << is_bv << std::endl;
#define BINOP(E)                                                               \
  [](ExprPtr a, ExprPtr b) -> ExprPtr { return mk_expr_ptr(E, {a, b}); }
    static std::unordered_map<std::string, BinOpF> binop_map = {
        {"add", BINOP(AddExpr)},   {"sub", BINOP(SubExpr)},
        {"mul", BINOP(MulExpr)},   {"sdiv", BINOP(DivExpr)},
        {"srem", BINOP(ModExpr)},  {"udiv", BINOP(UDivExpr)},
        {"urem", BINOP(UModExpr)}, {"and", BINOP(AndExpr)},
        {"or", BINOP(OrExpr)},     {"xor", BINOP(XorExpr)},
        {"shl", BINOP(LshExpr)},   {"lshr", BINOP(LRshExpr)},
        {"ashr", BINOP(ARshExpr)},
    };
#undef BINOP
    if (binop_map.find(opstring) != binop_map.end()) {
      auto binop_func = binop_map.find(opstring)->second;
      auto result = binop_func(op1.get_val(), op2.get_val());
      state->set_reg_val(dst_reg, RegValue{result});
      state->inst_iter++;
      nexts.push_back(state);
      if (opstring == "xor") {
        Z3Context ctx;
        auto a1 = gen_z3_expr(ctx, op1.get_val());
        auto a2 = gen_z3_expr(ctx, op2.get_val());
        // std::cout << "xor oprands: " << a1.get_expr().simplify() << ", " <<
        // a2.get_expr().simplify() << std::endl; std::cout << is_bv <<
        // std::endl; std::cout << "result ptr: " << result << std::endl;
        // std::cout << gen_z3_expr(ctx, result).get_expr().simplify() <<
        // std::endl;
      }
    } else {
      throw ExecError{"Unknown Binop"};
    }
  }

  void visitSelectInst(const llvm::SelectInst &inst) {
    auto dst = get_name(inst);
    auto cond = state->get_reg_val(*inst.getCondition());
    auto t_val = state->get_reg_val(*inst.getTrueValue());
    auto f_val = state->get_reg_val(*inst.getFalseValue());

    state->inst_iter++;
    auto t_ctx = state->copy_self();
    t_ctx->set_reg_val(dst, t_val);
    t_ctx->add_pre_cond(cond.get_val());
    nexts.push_back(t_ctx);

    auto f_ctx = state->copy_self();
    f_ctx->set_reg_val(dst, f_val);
    f_ctx->add_pre_cond(mk_expr_ptr(LNotExpr, cond.get_val()));
    nexts.push_back(f_ctx);
  }

  void visitUnreachableInst(const llvm::UnreachableInst &inst) {
    throw ExecError{"Unreachable"};
  }

  void visitCallInst(const llvm::CallInst &inst) {
    int num_args = inst.getNumArgOperands();
    std::vector<RegValue> params;
    llvm::Function *fp = inst.getCalledFunction();
    std::string func_name;
    if (fp == NULL) {
      const llvm::Value *v = inst.getCalledValue()->stripPointerCasts();
      llvm::StringRef fname = v->getName();
      func_name = fname.str();
    } else {
      func_name = fp->getName().str();
    }

    std::string dst_reg = "";
    if (inst.getType()->getTypeID() != llvm::Type::TypeID::VoidTyID) {
      dst_reg = get_name(inst);
    }
    if (func_name[0] == '@') {
      func_name = func_name.substr(1);
    }
    std::string raw_name = func_name;
    std::string demangled = demangle_cpp_name(func_name);
    if (demangled != "") {
      func_name = demangled;
    }
    if (func_name == "printf" || func_name == "click_chatter") {
      state->inst_iter++;
      nexts.push_back(state);
      return;
    }
    if (func_name == "std::ostream::operator<<(long)") {
      state->inst_iter++;
      nexts.push_back(state);
      return;
    }

    if (func_name == "llvm.dbg.declare") {
      state->inst_iter++;
      nexts.push_back(state);
      return;
    }
    if (func_name == "llvm.dbg.value") {
      state->inst_iter++;
      nexts.push_back(state);
      return;
    }

    if (is_prefix(func_name, "llvm.lifetime.")) {
      state->inst_iter++;
      nexts.push_back(state);
      return;
    }

    if (func_name == "__assert_fail") {
      state->is_assert_fail = true;
      state->finished_execution = true;
      nexts.push_back(state);
      return;
    }

    for (int i = 0; i < num_args; i++) {
      auto val = state->get_reg_val(*inst.getArgOperand(i));
      params.push_back(val);
    }
    // Check if there are matching "abstract functions"
    auto args = split_template(func_name);

    if (fp == nullptr && inst.isInlineAsm()) {
      auto val = inst.getCalledValue();
      auto asm_inst = llvm::dyn_cast<llvm::InlineAsm>(val);
      assert(asm_inst != nullptr);
      std::cout << "Asm Inst: " << asm_inst << " " << asm_inst->getAsmString()
                << std::endl;
      func_name = asm_inst->getAsmString();
    }

    // TODO: abstract function calls such as vector::size(), vector::operator[],
    // etc
    if (SymExecFunctions::get()->is_abstract_function(func_name)) {
      auto ns_list = SymExecFunctions::get()->run_function(state, func_name,
                                                           dst_reg, params);
      for (auto &ns : ns_list) {
        nexts.push_back(ns);
      }
      return;
    }

    // if control reached here, we have to "inline" the function call
    assert(fp != nullptr);
    // for (int i = 0; i < state->call_stack.size(); i++) {
    //     std::cout << "  ";
    // }
    // std::cout << "Calling function: " << func_name << std::endl;

    if (fp->isDeclaration()) {
      // The function body is in another module
      fp = irdb.get_fn_by_name(func_name);
      assert(fp != nullptr);
    }

    if (count_log_write) {
      // std::cout << "Calling " << func_name << std::endl;
      // try to find the bound
      if (BoundRegistry::get()->have_record(func_name)) {
        LogWriteBound bound;
        int max_log_op =
            BoundRegistry::get()->find_bound(func_name, state, params, bound);
        if (max_log_op >= 0) {
          // std::cout << "found bound " << max_log_op << std::endl;
          auto cnt = state->find_pointee(log_write_cnt_name);
          auto cnt_val = cnt->load(mk_concrete_bv(64, 0), 8).get_val();
          auto delta = mk_bv_var(64, state->name_gen("new_cnt"));
          auto in_bound =
              mk_expr_ptr(UleExpr, {delta, mk_concrete_bv(64, max_log_op)});

          auto new_cnt = mk_expr_ptr(AddExpr, {cnt_val, delta});
          cnt->store(mk_concrete_bv(64, 0), RegValue{new_cnt});
          state->add_pre_cond(in_bound);

          // check return type and generate symbolic value
          RegValue ret_val;
          if (dst_reg != "") {
            auto rt = inst.getType();
            assert(rt->isIntegerTy());
            auto bw = rt->getIntegerBitWidth();
            ret_val =
                RegValue{mk_bv_var(bw, state->name_gen(func_name + "_ret_"))};
          }
          state->add_pre_cond(bound.post_cond(params, ret_val));
          if (dst_reg != "") {
            state->set_reg_val(dst_reg, ret_val);
          }

          // auto shm_buf_name = state->shm_mem->name;
          // auto new_shm =
          // std::make_shared<Buffer>(state->name_gen(shm_buf_name), 0, 8);
          // state->shm_mem = new_shm;
          // state->objects[shm_buf_name] = new_shm;

          state->inst_iter++;
          nexts.push_back(state);
          return;
        }
      }
    }

    // first store current ctx
    ExecutionState::Context ctx;
    ctx.registers = state->registers;
    ctx.inst_iter = state->inst_iter;
    ctx.bb_end = state->bb_end;
    ctx.ret_val_reg = dst_reg;
    ctx.function_name = func_name;
    state->call_stack.push(ctx);

    // set params
    state->registers.clear();
    for (int i = 0; i < params.size(); i++) {
      auto reg_name = "%" + std::to_string(i);
      state->set_reg_val(reg_name, params[i]);
    }

    // now find the starting bb
    state->init_with_fn(fp);
    nexts.push_back(state);
  }
};

CrashVerifier::CrashVerifier(std::unique_ptr<IRDataBase> db)
    : irdb_(std::move(db)) {}

struct Z3RunnerWorkerState {
  struct Task {
    std::string task_desc;
    Symbolic::ExprPtr pre_cond;
    Symbolic::ExprPtr goal;
    std::shared_ptr<ExecutionState> crash_state;
    std::shared_ptr<ExecutionState> recovered_state;
  };
  std::mutex q_lock;
  std::queue<Task> task_queue;
  int batch_size;
  int n_worker;
  std::vector<Task> failed_states;
};

void z3_worker_fn(Z3RunnerWorkerState *state) {
  std::vector<Z3RunnerWorkerState::Task> failed_states;
  std::queue<Z3RunnerWorkerState::Task> local_q;
  Symbolic::Z3Context ctx;
  while (true) {
    if (local_q.empty()) {
      std::lock_guard<std::mutex> lg(state->q_lock);
      if (state->task_queue.empty()) {
        break;
      } else {
        int n_fetched = 0;
        while (n_fetched <= state->batch_size && !state->task_queue.empty()) {
          auto t = state->task_queue.front();
          state->task_queue.pop();
          local_q.push(t);
          n_fetched++;
        }
      }
      continue;
    }
    auto t = local_q.front();
    local_q.pop();
    std::cout << "Verifying: " << t.task_desc << std::endl;
    auto verified = verify_with_z3(ctx, t.pre_cond, t.goal);
    if (!verified) {
      failed_states.push_back(t);
    }
  }
  std::lock_guard<std::mutex> lg(state->q_lock);
  for (auto t : failed_states) {
    state->failed_states.push_back(t);
  }
}

bool CrashVerifier::verify_crash_safe(
    const std::string &fn, const std::string &r_fn,
    std::shared_ptr<ExecutionState> init_state, int num_worker) {
  auto handler_fn = irdb_->get_fn_by_name(fn);
  auto recover_fn = irdb_->get_fn_by_name(r_fn);

  init_state->init_with_fn(handler_fn);
  auto result_states_unfiltered = run(init_state, num_worker);
  std::vector<std::shared_ptr<ExecutionState>> result_states;

  // TODO: is skipping assert_fail state the right decision?
  for (int i = 0; i < result_states_unfiltered.size(); i++) {
    auto &s = result_states_unfiltered[i];
    if (s->is_assert_fail) {
      continue;
    }
    result_states.push_back(s);
  }

  std::cout << "Got " << result_states.size() << " states from handler"
            << std::endl;
  Symbolic::Z3Context ctx;
  Z3RunnerWorkerState thread_state;
  thread_state.n_worker = num_worker;
  thread_state.batch_size = 4;

  for (int i = 0; i < result_states.size(); i++) {
    auto &s = result_states[i];
    std::cout << i << "-th state have " << s->crashed_states.size()
              << " crashed states" << std::endl;
    assert(!s->is_assert_fail);
    // std::cout << "first few bytes of log: ";
    // Symbolic::print_expr_z3(s->log_mem->load_be(mk_concrete_bv(64, 0),
    // 2).get_val(), std::cout); std::cout << std::endl;
    for (int j = 0; j < s->crashed_states.size(); j++) {
      auto &cs_orig = s->crashed_states[j];
      auto cs = cs_orig->copy_self();
      // run recovery on crashed state
      cs->init_with_fn(recover_fn);
      cs->registers.clear();
      cs->call_stack = {};
      cs->set_reg_val("%0", RegValue{SymPointer(init_state->shm_mem->name)});
      cs->set_reg_val("%1", RegValue{SymPointer(init_state->log_mem->name)});

      // TODO: clear all buffers except shm_mem and log_mem
      auto recovered_states = run(cs, num_worker);
      std::cout << "  " << j << "-th crashed state returns "
                << recovered_states.size() << " traces after recovery"
                << std::endl;
      for (auto k = 0; k < recovered_states.size(); k++) {
        std::cout << "    "
                  << "Generating Task " << i << "-" << j << "-" << k
                  << std::endl;
        auto &rs = recovered_states[k];
        // either shm_mem equals to init state or result state
        auto shm_init = init_state->shm_mem;
        auto shm_recovered = rs->shm_mem;
        auto shm_nocrash = s->shm_mem;

        auto idx = mk_bv_var(64, init_state->name_gen("shm_eq_idx"));
        auto init_v = shm_init->load(idx, 1).get_val();
        auto recovered_v = shm_recovered->load(idx, 1).get_val();
        auto nocrash_v = shm_nocrash->load(idx, 1).get_val();

        auto all = mk_expr_ptr(EqExpr, {recovered_v, nocrash_v});
        auto nothing = mk_expr_ptr(EqExpr, {recovered_v, init_v});

        auto pre_cond =
            mk_expr_ptr(LAndExpr, {s->get_pre_cond(), rs->get_pre_cond()});
        auto goal = mk_expr_ptr(LOrExpr, {all, nothing});

        Z3RunnerWorkerState::Task task;
        task.pre_cond = pre_cond;
        task.goal = goal;
        task.crash_state = cs_orig;
        task.recovered_state = rs;
        std::stringstream ss;
        ss << "State " << i << "-" << j << "-" << k;
        task.task_desc = ss.str();
        thread_state.task_queue.push(task);
        /*
        auto verified = verify_with_z3(ctx, pre_cond, goal);
        if (!verified) {
          // TODO: need better error message
          std::cerr << "not ok" << std::endl;
          return false;
        }
        */
      }
    }
  }

  std::cout << "Starting verification workers" << std::endl;
  std::vector<std::thread> threads;
  for (int i = 0; i < num_worker; i++) {
    threads.push_back(std::thread(z3_worker_fn, &thread_state));
  }

  for (int i = 0; i < num_worker; i++) {
    threads[i].join();
  }
  if (thread_state.failed_states.size() > 0) {
    std::cerr << "not ok" << std::endl;
    for (int i = 0; i < thread_state.failed_states.size(); i++) {
      auto &t = thread_state.failed_states[i];
      auto &cs = t.crash_state;
      auto loc = get_inst_loc(*cs->inst_iter);
      llvm::errs() << "crash_point " << i << " : " << std::get<0>(loc) << ":"
                   << std::get<1>(loc) << "\n";
      llvm::errs() << "crashing inst : ";
      cs->inst_iter->print(llvm::errs());
      llvm::errs() << "\n";
      llvm::errs() << "==========================\n";
    }
    return false;
  }
  return true;
}

struct SymExecWorkerState {
  std::mutex q_lock;
  std::deque<std::shared_ptr<ExecutionState>> q;
  int n_worker;
  std::vector<bool> is_idle;
  int batch_size;
  CrashVerifier *verifier;
  std::vector<std::shared_ptr<ExecutionState>> result;
  std::atomic_int num_idle = 0;
  bool skip_pre_cond_check;
};

void crash_verifier_worker(int tid, SymExecWorkerState *state) {
  std::vector<std::shared_ptr<ExecutionState>> result;
  std::deque<std::shared_ptr<ExecutionState>> local_q;
  std::vector<std::shared_ptr<ExecutionState>> to_global;
  Symbolic::Z3Context ctx;
  while (true) {
    if (local_q.empty()) {
      int n_fetched = 0;
      {
        std::lock_guard<std::mutex> lg(state->q_lock);
        while (n_fetched < state->batch_size && !state->q.empty()) {
          auto s = state->q.front();
          state->q.pop_front();
          local_q.push_back(s);
          n_fetched++;
        }
      }
      if (n_fetched == 0) {
        state->is_idle[tid] = true;
        bool all_idle = true;
        for (int i = 0; i < state->n_worker; i++) {
          all_idle = all_idle && state->is_idle[i];
        }
        if (all_idle) {
          break;
        }
      } else {
        state->is_idle[tid] = false;
      }
      continue;
    }
    auto s = local_q.front();
    local_q.pop_front();

    if (!state->skip_pre_cond_check && s->have_new_cond) {
      Symbolic::Z3Context ctx;
      z3::solver sol(ctx.ctx);
      sol.add(gen_z3_expr(ctx, s->get_pre_cond()).get_bool().simplify());
      if (sol.check() == z3::unsat) {
        continue;
      }
      s->have_new_cond = false;
    }

    auto ns_list = state->verifier->single_step(s);
    for (int i = ns_list.size() - 1; i >= 0; i--) {
      auto &ns = ns_list[i];
      // check if ns is a possible state (pre condition is satisfiable)
      /*
      if (ns->have_new_cond) {
        auto pre_cond = ns->get_pre_cond();
        z3::solver sol(ctx.ctx);
        sol.add(gen_z3_expr(ctx, pre_cond).get_bool());
        if (sol.check() == z3::unsat) {
          continue;
        } else {
          ns->have_new_cond = false;
        }
      }
      */
      if (ns->finished_execution) {
        result.push_back(ns);
      } else {
        if (local_q.size() < state->batch_size) {
          local_q.push_front(ns);
        } else {
          to_global.push_back(ns);
        }
      }
    }

    {
      std::lock_guard<std::mutex> lg(state->q_lock);
      for (auto ns : to_global) {
        state->q.push_front(ns);
      }
    }
    to_global.clear();
  }

  {
    std::lock_guard<std::mutex> lg(state->q_lock);
    for (auto s : result) {
      state->result.push_back(s);
    }
  }
}

StatePtrList CrashVerifier::run(std::shared_ptr<ExecutionState> init_state,
                                int num_workers, bool skip_pre_cond_check) {
  SymExecWorkerState state;
  std::vector<std::thread> threads;
  assert(num_workers > 0);
  state.q.push_back(init_state);
  state.batch_size = 2;
  state.n_worker = num_workers;
  state.verifier = this;
  state.skip_pre_cond_check = skip_pre_cond_check;
  for (int i = 0; i < num_workers; i++) {
    state.is_idle.push_back(false);
  }
  for (int i = 0; i < num_workers; i++) {
    threads.push_back(std::thread(crash_verifier_worker, i, &state));
  }
  for (int i = 0; i < num_workers; i++) {
    threads[i].join();
  }
  return state.result;
  /*
  StatePtrList result;
  std::queue<std::shared_ptr<ExecutionState>> q;
  q.push(init_state);

  while (!q.empty()) {
    auto s = q.front();
    q.pop();

    auto ns_list = single_step(s);
    for (auto ns : ns_list) {
      // check if ns is a possible state (pre condition is satisfiable)
      if (!ns->is_valid()) {
        continue;
      }
      if (ns->finished_execution) {
        result.push_back(ns);
      } else {
        q.push(ns);
      }
    }
  }
  return result;
  */
}

StatePtrList CrashVerifier::single_step(std::shared_ptr<ExecutionState> state) {
  StatePtrList result;
  assert(state->inst_iter != state->bb_end);
  // if (!state->is_valid()) {
  //   return {};
  // }
  auto &inst = *(state->inst_iter);
  // llvm::outs() << &*state->inst_iter << "\n";
  // inst.print(llvm::outs());
  // auto loc = get_inst_loc(inst);
  // llvm::outs() << " @ " << std::get<0>(loc) << ":" << std::get<1>(loc) <<
  // "\n";
  SymExecVisitor visitor(state, result, *irdb_);
  visitor.visit(inst);
  return result;
}

LogOpCounter::LogOpCounter(std::unique_ptr<IRDataBase> db)
    : irdb_(std::move(db)) {}

StatePtrList LogOpCounter::run(std::shared_ptr<ExecutionState> init_state,
                               int num_workers) {
  StatePtrList result;
  std::deque<std::shared_ptr<ExecutionState>> q;
  q.push_back(init_state);

  while (!q.empty()) {
    auto s = q.front();
    q.pop_front();

    if (s->have_new_cond) {
      Symbolic::Z3Context ctx;
      z3::solver sol(ctx.ctx);
      sol.add(gen_z3_expr(ctx, s->get_pre_cond()).get_bool().simplify());
      // std::cout << gen_z3_expr(ctx, s->get_pre_cond()).get_bool() <<
      // std::endl;
      if (sol.check() == z3::unsat) {
        continue;
      }
      s->have_new_cond = false;
    }

    auto ns_list = single_step(s);
    for (int i = ns_list.size() - 1; i >= 0; i--) {
      auto &ns = ns_list[i];
      if (ns->finished_execution) {
        result.push_back(ns);
      } else {
        q.push_front(ns);
      }
    }
  }
  return result;
}

StatePtrList LogOpCounter::single_step(std::shared_ptr<ExecutionState> state) {
  StatePtrList result;
  assert(state->inst_iter != state->bb_end);
  // if (!state->is_valid()) {
  //   return {};
  // }
  auto &inst = *(state->inst_iter);
  /*
  llvm::outs() << &*state->inst_iter << "\n";
  inst.print(llvm::outs());
  auto loc = get_inst_loc(inst);
  llvm::outs() << " @ " << std::get<0>(loc) << ":" << std::get<1>(loc) <<
  "\n";
  */
  SymExecVisitor visitor(state, result, *irdb_);
  visitor.count_log_write = true;
  visitor.visit(inst);
  return result;
}
