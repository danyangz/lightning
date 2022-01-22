#include "logwrite_bound.h"
#include "data-structures.h"

std::unique_ptr<BoundRegistry> BoundRegistry::instance = nullptr;

BoundRegistry *BoundRegistry::get() {
  if (BoundRegistry::instance == nullptr) {
    BoundRegistry::instance = std::make_unique<BoundRegistry>();
  }
  return BoundRegistry::instance.get();
}

bool BoundRegistry::have_record(const std::string &fn) const {
  return bounds_.find(fn) != bounds_.end();
}

int BoundRegistry::find_bound(const std::string &fn,
                              std::shared_ptr<ExecutionState> &s,
                              const std::vector<RegValue> &params,
                              LogWriteBound &bound) {
  auto iter = bounds_.find(fn);
  if (iter == bounds_.end()) {
    // try again after demangle
    auto demangled = demangle_cpp_name(fn);
    iter = bounds_.find(demangled);
  }
  if (iter == bounds_.end()) {
    return -1;
  }

  auto &b = iter->second;
  auto pre_cond = b.pre_cond(params);

  Symbolic::Z3Context ctx;
  int verified = verify_with_z3(ctx, nullptr, pre_cond);
  if (!verified) {
    return -1;
  }

  // reset the entire shm_mem
  // auto shm_buf_name = s->shm_mem->name;
  // auto new_shm = std::make_shared<Buffer>(shm_buf_name);
  // s->shm_mem = new_shm;
  // s->objects[shm_buf_name] = new_shm;
  bound = b;
  return b.bound;
}

void BoundRegistry::add_bound(const std::string &fn,
                              const LogWriteBound &bound) {
  assert(bounds_.find(fn) == bounds_.end());
  bounds_.insert({fn, bound});
}

void verify_num_logwrite_bound(LogOpCounter *verifier,
                               std::shared_ptr<ExecutionState> init_state,
                               int bound) {
  auto cnt = std::make_shared<ConcreteCacheBuffer>(log_write_cnt_name);
  init_state->add_pointee(cnt);
  cnt->store(mk_concrete_bv(64, 0), RegValue{mk_concrete_bv(64, 0)});

  auto states = verifier->run(init_state);

  Symbolic::Z3Context ctx;
  for (auto &s : states) {
    auto cnt = s->find_pointee(log_write_cnt_name);
    auto cnt_val = cnt->load(mk_concrete_bv(64, 0), 8).get_val();
    auto goal = mk_expr_ptr(UltExpr, {cnt_val, mk_concrete_bv(64, bound)});

    int verified = verify_with_z3(ctx, s->get_pre_cond(), goal);
    if (!verified) {
      std::cerr << "not ok" << std::endl;
      assert(false);
    }
  }
}

void verify_num_logwrite_bound(LogOpCounter *verifier,
                               std::shared_ptr<ExecutionState> init_state,
                               const std::vector<RegValue> &params,
                               const LogWriteBound &bound) {
  auto cnt = std::make_shared<ConcreteCacheBuffer>(log_write_cnt_name);
  init_state->add_pointee(cnt);
  for (int i = 0; i < params.size(); i++) {
    auto reg_name = "%" + std::to_string(i);
    init_state->set_reg_val(reg_name, params[i]);
  }
  cnt->store(mk_concrete_bv(64, 0), RegValue{mk_concrete_bv(64, 0)});

  init_state->add_pre_cond(bound.pre_cond(params));

  auto states = verifier->run(init_state);

  Symbolic::Z3Context ctx;
  for (int i = 0; i < states.size(); i++) {
    auto &s = states[i];
    std::cout << "Verifying case " << i << "...             \r" << std::flush;
    auto cnt = s->find_pointee(log_write_cnt_name);
    auto cnt_val = cnt->load(mk_concrete_bv(64, 0), 8).get_val();
    auto goal =
        mk_expr_ptr(UleExpr, {cnt_val, mk_concrete_bv(64, bound.bound)});

    int verified = verify_with_z3(ctx, s->get_pre_cond(), goal);
    if (!verified) {
      std::cerr << "\nnot ok                  " << std::endl;
      assert(false);
    }
    verified = verify_with_z3(ctx, s->get_pre_cond(),
                              bound.post_cond(params, s->ret_val));
    if (!verified) {
      std::cerr << "\npost cond not ok        " << std::endl;
      assert(false);
    }
  }
  std::cout << std::endl;
}

void init_execution_state(std::shared_ptr<ExecutionState> &s) {
  auto client_obj = std::make_shared<AbstractObject>("client");
  auto allocator_obj = std::make_shared<AbstractObject>("allocator_");
  auto disk_obj = std::make_shared<AbstractObject>("log_disk_");
  auto obj_log_obj = std::make_shared<AbstractObject>("object_log_");

  s->add_pointee(client_obj);
  s->add_pointee(allocator_obj);
  s->add_pointee(disk_obj);
  s->add_pointee(obj_log_obj);

  client_obj->add_ptr_at(s, SymPointer{s->shm_mem->name}, 16);
  client_obj->add_obj_ptr_at(s, allocator_obj, 32);
  client_obj->add_ptr_at(s, SymPointer{s->shm_mem->name}, 40);
  client_obj->add_ptr_at(s, SymPointer{obj_log_obj->name}, 64);
  client_obj->add_ptr_at(s, SymPointer{disk_obj->name}, 80);

  SymPointer base_ptr{s->shm_mem->name};
  base_ptr.is_shm_ptr = true;

  SymPointer free_list_ptr{s->shm_mem->name};
  free_list_ptr.offset = mk_concrete_bv(64, 8);
  free_list_ptr.is_shm_ptr = true;

  allocator_obj->add_ptr_at(s, base_ptr, 0);
  allocator_obj->add_ptr_at(s, free_list_ptr, 8);
  allocator_obj->add_ptr_at(s, base_ptr, 16);
  allocator_obj->add_ptr_at(s, SymPointer{disk_obj->name}, 24);

  auto obj_log_content =
      std::make_shared<Buffer>(s->name_gen("obj_log_content"));
  auto obj_log_mem = std::make_shared<Buffer>("object_log_mem_");
  s->add_pointee(obj_log_content);
  s->add_pointee(obj_log_mem);

  using Region = AbstractObject::Region;
  obj_log_obj->add_region(
      Region{Region::T::INLINED, 0, 12, SymPointer{obj_log_content->name}});
  obj_log_obj->add_obj_ptr_at(s, obj_log_mem, 16);
  obj_log_obj->add_obj_ptr_at(s, disk_obj, 24);
}
