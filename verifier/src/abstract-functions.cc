#include "abstract-functions.h"
#include "data-structures.h"

std::unique_ptr<SymExecFunctions> SymExecFunctions::instance = nullptr;

std::string log_write_cnt_name = "__special_countet_num_log_write";

SymExecFunctions *SymExecFunctions::get() {
  if (instance == nullptr) {
    instance = std::make_unique<SymExecFunctions>();
  }
  return instance.get();
}

void SymExecFunctions::add_readonly_function(const std::string &func_name) {
  readonly_funcs_.insert(func_name);
}

bool SymExecFunctions::is_abstract_function(const std::string &func_name) {
  if (readonly_funcs_.find(func_name) != readonly_funcs_.end()) {
    return true;
  }

  if (counting_mode) {
    if (is_prefix(func_name, "UndoLogDisk::") ||
        is_prefix(func_name, "RedoLogDisk::")) {
      return true;
    }
  }
  if (is_prefix(func_name, "std::vector<")) {
    return true;
  }

  if (func_name == "sem_post" || func_name == "sem_destroy" ||
      func_name == "sem_init") {
    return true;
  }
  return false;
}

StatePtrList SymExecFunctions::run_function(
    std::shared_ptr<ExecutionState> s, const std::string &fn,
    const std::string &dst_reg, const std::vector<RegValue> &params) {
  std::string func_name = fn;
  if (readonly_funcs_.find(func_name) != readonly_funcs_.end()) {
    s->set_reg_val(dst_reg,
                   RegValue{mk_bv_var(64, name_gen_(func_name + "_ret"))});
    // auto shm_buf_name = s->shm_mem->name;
    // SymPointer ptr;
    // ptr.pointer_base = shm_buf_name;
    // ptr.offset = mk_bv_var(64, name_gen_(func_name));
    // ptr.is_shm_ptr = true;
    // s->set_reg_val(dst_reg, RegValue{ptr});
    s->inst_iter++;
    return {s};
  }
  if (log_write_bounds.find(func_name) != log_write_bounds.end()) {
    auto bound = log_write_bounds.find(func_name)->second;
    auto cnt = s->find_pointee(log_write_cnt_name)
                   ->load(mk_concrete_bv(64, 0), 8)
                   .get_val();
    auto delta = mk_bv_var(64, s->name_gen("new_cnt"));
    auto in_bound = mk_expr_ptr(UltExpr, {delta, mk_concrete_bv(64, bound)});

    auto new_cnt = mk_expr_ptr(AddExpr, {cnt, delta});
    s->find_pointee(log_write_cnt_name)
        ->store(mk_concrete_bv(64, 0), RegValue{new_cnt});
    s->add_pre_cond(in_bound);

    // TODO: use symbolic states for all memory objects
    //
    s->inst_iter++;
    return {s};
  }

  if (is_prefix(func_name, "UndoLogDisk::") ||
      is_prefix(func_name, "RedoLogDisk::")) {
    auto pos = func_name.find("::");
    pos += 2;
    auto method_name = func_name.substr(pos);
    if (is_prefix(method_name, "Write(")) {
      auto cnt = s->find_pointee(log_write_cnt_name)
                     ->load(mk_concrete_bv(64, 0), 8)
                     .get_val();
      auto new_cnt = mk_expr_ptr(AddExpr, {cnt, mk_concrete_bv(64, 1)});
      s->find_pointee(log_write_cnt_name)
          ->store(mk_concrete_bv(64, 0), RegValue{new_cnt});
      s->inst_iter++;
      return {s};
    }
  }

  if (func_name == "sem_post" || func_name == "sem_destroy" ||
      func_name == "sem_init") {
    s->set_reg_val(dst_reg, RegValue{mk_concrete_bv(32, 0)});
    s->inst_iter++;
    return {s};
  }

  if (is_prefix(func_name, "std::vector<")) {
    auto vec_ptr = params[0].get_ptr();
    auto obj = s->find_pointee(vec_ptr.pointer_base);
    assert(!vec_ptr.offset->simplify()->is_symbolic());
    assert(std::dynamic_pointer_cast<Symbolic::ConcreteBv>(
               vec_ptr.offset->simplify())
               ->get_val() == 0);
    assert(obj->type() == PointeeType::Vector);
    auto vec = std::dynamic_pointer_cast<AbstractVector>(obj);
    func_name = func_name.substr(std::string("std::").length());
    auto pos = func_name.find(">::");
    if (pos != std::string::npos) {
      auto method_name = func_name.substr(pos + std::string(">::").length());
      if (method_name == "size() const") {
        s->set_reg_val(dst_reg, RegValue{vec->n_elements});
        s->inst_iter++;
        return {s};
      } else if (is_prefix(method_name, "operator[]")) {
        auto val = vec->get(params[1].get_val());
        auto val_size = vec->val_type->get_bv_width();
        auto result_buf =
            std::make_shared<Buffer>(s->name_gen("vec_result"), val_size / 8);
        s->add_pointee(result_buf);
        result_buf->store_be(mk_concrete_bv(64, 0), RegValue{val});
        s->set_reg_val(dst_reg, RegValue{SymPointer{result_buf->name}});
        s->inst_iter++;
        return {s};
      }
    }
  }
  assert(false && "unknown function");
}
