#include "abstract-functions.h"
#include "data-structures.h"
#include "executor.h"
#include "llvm-helpers.h"
#include "logwrite_bound.h"
#include "symbolic-expr.h"
#include "z3-gen.h"

using Region = AbstractObject::Region;

void create_block_bound(LogOpCounter *verifier,
                        bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name = "MemAllocator::create_block(long, unsigned long)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  // set up object state
  auto init_state = std::make_shared<ExecutionState>(name_gen);
  init_execution_state(init_state);

  // set up function arguments
  auto fn = verifier->irdb()->get_fn_by_name(fn_name);
  init_state->init_with_fn(fn);

  std::vector<RegValue> params;

  params.push_back(RegValue{SymPointer("allocator_")});
  params.push_back(RegValue{mk_bv_var(64, name_gen("start"))});
  params.push_back(RegValue{mk_bv_var(64, name_gen("size"))});

  LogWriteBound bound;
  bound.bound = 40;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  if (!skip_verification) {
    verify_num_logwrite_bound(verifier, init_state, params, bound);
  } else {
    std::cout << "Skipping" << std::endl;
  }

  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void add_to_free_list_bound(LogOpCounter *verifier,
                            bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name = "MemAllocator::add_to_free_list(int, long)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  // set up object state
  auto init_state = std::make_shared<ExecutionState>(name_gen);
  init_execution_state(init_state);

  // set up function arguments
  auto fn = verifier->irdb()->get_fn_by_name(fn_name);
  init_state->init_with_fn(fn);

  auto index = mk_bv_var(32, name_gen("index"));
  auto offset = mk_bv_var(64, name_gen("offset"));

  std::vector<RegValue> params;

  params.push_back(RegValue{SymPointer("allocator_")});
  params.push_back(RegValue{index});
  params.push_back(RegValue{offset});

  LogWriteBound bound;
  bound.bound = 3;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  if (!skip_verification) {
    verify_num_logwrite_bound(verifier, init_state, params, bound);
  } else {
    std::cout << "Skipping" << std::endl;
  }

  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void separate_buddy_bound(LogOpCounter *verifier,
                          bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name = "MemAllocator::separate_buddy(long, int)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  // set up object state
  auto init_state = std::make_shared<ExecutionState>(name_gen);
  init_execution_state(init_state);

  // set up function arguments
  auto fn = verifier->irdb()->get_fn_by_name(fn_name);
  init_state->init_with_fn(fn);

  auto offset = mk_bv_var(64, name_gen("offset"));
  auto index = mk_bv_var(32, name_gen("index"));

  std::vector<RegValue> params;

  params.push_back(RegValue{SymPointer("allocator_")});
  params.push_back(RegValue{offset});
  params.push_back(RegValue{index});

  LogWriteBound bound;
  bound.bound = 43;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  if (!skip_verification) {
    verify_num_logwrite_bound(verifier, init_state, params, bound);
  } else {
    std::cout << "Skipping" << std::endl;
  }

  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void get_free_block_bound(LogOpCounter *verifier,
                          bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name = "MemAllocator::get_free_block(int)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  // set up object state
  auto init_state = std::make_shared<ExecutionState>(name_gen);
  init_execution_state(init_state);

  // set up function arguments
  auto fn = verifier->irdb()->get_fn_by_name(fn_name);
  init_state->init_with_fn(fn);

  std::vector<RegValue> params;

  params.push_back(RegValue{SymPointer("allocator_")});
  params.push_back(RegValue{mk_bv_var(32, name_gen("index"))});

  LogWriteBound bound;
  bound.bound = 1500;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_expr_ptr(UltExpr, {params[1].get_val(), mk_concrete_bv(32, 64)});
  };

  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  if (!skip_verification) {
    verify_num_logwrite_bound(verifier, init_state, params, bound);
  } else {
    std::cout << "Skipping" << std::endl;
  }

  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void malloc_shared_bound(LogOpCounter *verifier,
                         bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name = "MemAllocator::MallocShared(unsigned long)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  // set up object state
  auto init_state = std::make_shared<ExecutionState>(name_gen);
  init_execution_state(init_state);

  // set up function arguments
  auto fn = verifier->irdb()->get_fn_by_name(fn_name);
  init_state->init_with_fn(fn);

  std::vector<RegValue> params;

  params.push_back(RegValue{SymPointer("allocator_")});
  params.push_back(RegValue{mk_bv_var(64, name_gen("size"))});

  LogWriteBound bound;
  bound.bound = 1550;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  if (!skip_verification) {
    verify_num_logwrite_bound(verifier, init_state, params, bound);
  } else {
    std::cout << "Skipping" << std::endl;
  }

  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void create_internal_bound(LogOpCounter *verifier,
                           bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name =
      "LightningClient::create_internal(unsigned long, long*, unsigned long)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  // set up object state
  auto init_state = std::make_shared<ExecutionState>(name_gen);
  init_execution_state(init_state);

  // set up function arguments
  auto fn = verifier->irdb()->get_fn_by_name(fn_name);
  init_state->init_with_fn(fn);

  auto object_id = mk_bv_var(64, name_gen("object_id"));
  auto offset_obj = std::make_shared<Buffer>(name_gen("offset_ptr"));
  auto size = mk_bv_var(64, name_gen("size"));

  init_state->add_pointee(offset_obj);

  std::vector<RegValue> params;
  params.push_back(RegValue{SymPointer("client")});
  params.push_back(RegValue{object_id});
  params.push_back(RegValue{SymPointer(offset_obj->name)});
  params.push_back(RegValue{size});

  LogWriteBound bound;
  bound.bound = 3200;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  if (!skip_verification) {
    verify_num_logwrite_bound(verifier, init_state, params, bound);
  } else {
    std::cout << "Skipping" << std::endl;
  }

  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void get_internal_bound(LogOpCounter *verifier,
                        bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name =
      "LightningClient::get_internal(unsigned long, long*, unsigned long*)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  // set up object state
  auto init_state = std::make_shared<ExecutionState>(name_gen);
  init_execution_state(init_state);

  // set up function arguments
  auto fn = verifier->irdb()->get_fn_by_name(fn_name);
  init_state->init_with_fn(fn);

  auto object_id = mk_bv_var(64, name_gen("object_id"));
  auto offset_obj = std::make_shared<Buffer>(name_gen("offset_ptr"));
  auto size_obj = std::make_shared<Buffer>(name_gen("size"));

  init_state->add_pointee(offset_obj);
  init_state->add_pointee(size_obj);

  std::vector<RegValue> params;

  params.push_back(RegValue{SymPointer("client")});
  params.push_back(RegValue{object_id});
  params.push_back(RegValue{SymPointer(offset_obj->name)});
  params.push_back(RegValue{SymPointer(size_obj->name)});

  LogWriteBound bound;
  bound.bound = 5;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  if (!skip_verification) {
    verify_num_logwrite_bound(verifier, init_state, params, bound);
  } else {
    std::cout << "Skipping" << std::endl;
  }

  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void remove_block_nolog_bound(LogOpCounter *verifier,
                              bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name = "MemAllocator::remove_block_nolog(int, long)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  assert(skip_verification);
  std::cout << "Skipping" << std::endl;

  LogWriteBound bound;
  bound.bound = 1;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };
  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };
  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void remove_block_bound(LogOpCounter *verifier,
                        bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name = "MemAllocator::remove_block(int, long)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  assert(skip_verification);
  std::cout << "Skipping" << std::endl;

  LogWriteBound bound;
  bound.bound = 1;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };
  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };
  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void merge_blocks_bound(LogOpCounter *verifier,
                        bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name = "MemAllocator::merge_blocks(long, long, int)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  // set up object state
  auto init_state = std::make_shared<ExecutionState>(name_gen);
  init_execution_state(init_state);

  // set up function arguments
  auto fn = verifier->irdb()->get_fn_by_name(fn_name);
  init_state->init_with_fn(fn);

  std::vector<RegValue> params;

  params.push_back(RegValue{SymPointer("allocator_")});
  params.push_back(RegValue{mk_bv_var(64, name_gen("block1_offset"))});
  params.push_back(RegValue{mk_bv_var(64, name_gen("block2_offset"))});
  params.push_back(RegValue{mk_bv_var(32, name_gen("index"))});

  LogWriteBound bound;
  bound.bound = 10;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  if (!skip_verification) {
    verify_num_logwrite_bound(verifier, init_state, params, bound);
  } else {
    std::cout << "Skipping" << std::endl;
  }

  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void fls_bound(LogOpCounter *verifier, bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name = "fls_uninlined(unsigned long)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  // set up object state
  auto init_state = std::make_shared<ExecutionState>(name_gen);
  init_execution_state(init_state);

  // set up function arguments
  auto fn = verifier->irdb()->get_fn_by_name(fn_name);
  init_state->init_with_fn(fn);

  std::vector<RegValue> params;

  params.push_back(RegValue{mk_bv_var(64, name_gen("size"))});

  LogWriteBound bound;
  bound.bound = 0;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    // return mk_concrete_bv(1, 1);
    return mk_expr_ptr(UleExpr, {r.get_val(), mk_concrete_bv(32, 64)});
  };

  if (!skip_verification) {
    verify_num_logwrite_bound(verifier, init_state, params, bound);
  } else {
    std::cout << "Skipping" << std::endl;
  }

  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void free_shared_bound(LogOpCounter *verifier, bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name = "MemAllocator::FreeShared(long)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  // set up object state
  auto init_state = std::make_shared<ExecutionState>(name_gen);
  init_execution_state(init_state);

  // set up function arguments
  auto fn = verifier->irdb()->get_fn_by_name(fn_name);
  init_state->init_with_fn(fn);

  std::vector<RegValue> params;

  params.push_back(RegValue{SymPointer("allocator_")});
  params.push_back(RegValue{mk_bv_var(64, name_gen("block_offset"))});

  LogWriteBound bound;
  bound.bound = 320;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  if (!skip_verification) {
    verify_num_logwrite_bound(verifier, init_state, params, bound);
  } else {
    std::cout << "Skipping" << std::endl;
  }

  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void delete_internal_bound(LogOpCounter *verifier,
                           bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name = "LightningClient::delete_internal(unsigned long)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  // set up object state
  auto init_state = std::make_shared<ExecutionState>(name_gen);
  init_execution_state(init_state);

  // set up function arguments
  auto fn = verifier->irdb()->get_fn_by_name(fn_name);
  init_state->init_with_fn(fn);

  auto object_id = mk_bv_var(64, name_gen("object_id"));

  std::vector<RegValue> params;

  params.push_back(RegValue{SymPointer("client")});
  params.push_back(RegValue{object_id});

  LogWriteBound bound;
  bound.bound = 650;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  if (!skip_verification) {
    verify_num_logwrite_bound(verifier, init_state, params, bound);
  } else {
    std::cout << "Skipping" << std::endl;
  }

  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void seal_internal_bound(LogOpCounter *verifier,
                         bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name = "LightningClient::seal_internal(unsigned long)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  // set up object state
  auto init_state = std::make_shared<ExecutionState>(name_gen);
  init_execution_state(init_state);

  // set up function arguments
  auto fn = verifier->irdb()->get_fn_by_name(fn_name);
  init_state->init_with_fn(fn);

  auto object_id = mk_bv_var(64, name_gen("object_id"));

  std::vector<RegValue> params;

  params.push_back(RegValue{SymPointer("client")});
  params.push_back(RegValue{object_id});

  LogWriteBound bound;
  bound.bound = 2;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  if (!skip_verification) {
    verify_num_logwrite_bound(verifier, init_state, params, bound);
  } else {
    std::cout << "Skipping" << std::endl;
  }

  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

void subscribe_internal_bound(LogOpCounter *verifier,
                              bool skip_verification = false) {
  NameFactory name_gen;
  std::string fn_name =
      "LightningClient::subscribe_internal(unsigned long, sem_t**, bool*)";

  std::cout << "Verifying bound for \"" << fn_name << "\"" << std::endl;

  // set up object state
  auto init_state = std::make_shared<ExecutionState>(name_gen);
  init_execution_state(init_state);

  // set up function arguments
  auto fn = verifier->irdb()->get_fn_by_name(fn_name);
  init_state->init_with_fn(fn);

  auto object_id = mk_bv_var(64, name_gen("object_id"));

  std::vector<RegValue> params;

  auto sem_mem = std::make_shared<PointerStore>("sem_mem");
  auto bool_mem = std::make_shared<Buffer>("bool_mem");
  init_state->add_pointee(sem_mem);
  init_state->add_pointee(bool_mem);

  params.push_back(RegValue{SymPointer("client")});
  params.push_back(RegValue{object_id});
  params.push_back(RegValue{SymPointer{sem_mem->name}});
  params.push_back(RegValue{SymPointer{bool_mem->name}});

  LogWriteBound bound;
  bound.bound = 10;
  bound.pre_cond =
      [](const std::vector<RegValue> &params) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  bound.post_cond = [](const std::vector<RegValue> &params,
                       RegValue &r) -> Symbolic::ExprPtr {
    return mk_concrete_bv(1, 1);
  };

  if (!skip_verification) {
    verify_num_logwrite_bound(verifier, init_state, params, bound);
  } else {
    std::cout << "Skipping" << std::endl;
  }

  std::cout << "# log write <= " << bound.bound << std::endl << std::endl;
  BoundRegistry::get()->add_bound(fn_name, bound);
}

int main(int argc, char *argv[]) {
  auto db = std::make_unique<IRDataBase>();
  db->load_ir_file("client.ll");
  db->load_ir_file("malloc.ll");
  db->load_ir_file("store.ll");
  db->load_ir_file("log_disk.ll");
  db->load_ir_file("object_log.ll");

  LogOpCounter verifier(std::move(db));

  SymExecFunctions::get()->counting_mode = true;

  SymExecFunctions::get()->add_readonly_function(
      "LightningClient::find_object(unsigned long)");
  SymExecFunctions::get()->add_readonly_function(
      "MemAllocator::find_prev_block(long, long)");
  SymExecFunctions::get()->add_readonly_function(
      "ObjectLog::find_object(long)");
  SymExecFunctions::get()->add_readonly_function(
      "ObjectLog::erase_object(long)");
  SymExecFunctions::get()->add_readonly_function(
      "ObjectLog::insert_object(long, long)");
  SymExecFunctions::get()->add_readonly_function(
      "ObjectLog::find_new_entry(long)");
  SymExecFunctions::get()->add_readonly_function(
      "RepetitiveSemPost(sem_t*, int)");

  /*
   * helpers that we assume to be correct
   * (potential unbounded loop due to linked list walk)
   */
  remove_block_nolog_bound(&verifier, true);
  remove_block_bound(&verifier, true);

  // helpers that we verify with symbolic execution
  create_block_bound(&verifier, false);
  add_to_free_list_bound(&verifier, false);
  separate_buddy_bound(&verifier, false);
  get_free_block_bound(&verifier, false);
  malloc_shared_bound(&verifier, false);

  fls_bound(&verifier, false);
  merge_blocks_bound(&verifier, false);
  free_shared_bound(&verifier, false);

  // top-level interfaces
  create_internal_bound(&verifier, false);
  get_internal_bound(&verifier, false);
  delete_internal_bound(&verifier, false);
  seal_internal_bound(&verifier, false);
  subscribe_internal_bound(&verifier, false);
  return 0;
}
