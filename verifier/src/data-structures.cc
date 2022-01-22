#include <algorithm>
#include <memory>

#include "data-structures.h"
#include "z3-gen.h"

using namespace Symbolic;

std::ostream &operator<<(std::ostream &os, const PointeeType &t) {
  switch (t) {
  case PointeeType::PointerStore:
    os << "PointerStore";
    break;
  case PointeeType::Vector:
    os << "Vector";
    break;
  case PointeeType::HashMap:
    os << "HashMap";
    break;
  case PointeeType::Buffer:
    os << "Buffer";
    break;
  case PointeeType::Packet:
    os << "Packet";
    break;
  case PointeeType::Object:
    os << "Object";
    break;
  case PointeeType::Invalid:
    os << "Invalid";
    break;
  }
  return os;
}

RegValue PointerStore::load(Symbolic::ExprPtr off, uint64_t size) const {
  throw "PointerStore: load not implemented";
}

void PointerStore::store(Symbolic::ExprPtr off, RegValue val) {
  throw "PointerStore: store not implemented";
}

PointerStore::MultiPtr PointerStore::load_ptr(Symbolic::ExprPtr off) const {
  MultiPtr result;
  uint64_t concrete_off = 0;
  const uint64_t ptr_size = 8;
  for (int i = 0; i < ptrs.size(); i++) {
    auto match = mk_expr_ptr(EqExpr, {mk_concrete_bv(64, concrete_off), off});

    MultiPtrEntry e;
    e.pre_cond = match;
    e.ptr = ptrs[i];
    result.push_back(e);

    concrete_off += ptr_size;
  }
  return result;
}

void PointerStore::print(std::ostream &os) const {
  os << "(PointerStore " << name << ")";
}

Inaccessible::Inaccessible(const std::string &n) { name = n; }

void Inaccessible::print(std::ostream &os) const {
  os << "(Inaccessible " << name << ")";
}

Buffer::Buffer(const std::string &name) {
  auto bv_64 = std::make_shared<BitVecType>(64);
  auto bv_8 = std::make_shared<BitVecType>(8);
  std::vector<std::shared_ptr<ValType>> kt_l = {bv_64};
  auto ft = std::make_shared<UFType>(kt_l, bv_8);
  auto uf = std::make_shared<SymbolicVar>(ft, name);
  Lambda::FuncT func = [uf](const OpApplyNode::ArgList &args) -> ExprPtr {
    return mk_expr_ptr(FuncApply, uf, args);
  };
  content_f = std::make_shared<Lambda>(ft, func);
  sized = false;
  size = 0;
  this->name = name;
}

Buffer::Buffer(const std::string &name, int sz, int _cell_size) {
  auto bv_64 = std::make_shared<BitVecType>(64);
  auto bv_val = std::make_shared<BitVecType>(8 * _cell_size);
  std::vector<std::shared_ptr<ValType>> kt_l = {bv_64};
  auto ft = std::make_shared<UFType>(kt_l, bv_val);
  auto uf = std::make_shared<SymbolicVar>(ft, name);
  Lambda::FuncT func = [uf](const OpApplyNode::ArgList &args) -> ExprPtr {
    return mk_expr_ptr(FuncApply, uf, args);
  };
  content_f = std::make_shared<Lambda>(ft, func);
  if (sz > 0) {
    sized = true;
    size = sz;
  } else {
    sized = false;
    size = 0;
  }
  cell_size = _cell_size;
  this->name = name;
}

RegValue Buffer::load_be(ExprPtr off, uint64_t size) const {
  assert(cell_size == 1);
  int num_loads = size;
  std::vector<ExprPtr> bytes;
  ExprPtr ptr = off;
  for (int i = 0; i < num_loads; i++) {
    auto b = mk_expr_ptr(FuncApply, content_f, {ptr});
    ptr = mk_expr_ptr(AddExpr, {ptr, mk_expr_ptr(ConcreteBv, 64, 1)});
    bytes.push_back(b);
  }
  return RegValue{mk_expr_ptr(ConcatExpr, bytes)};
}

void Buffer::store_be(ExprPtr off, RegValue val) {
  assert(cell_size == 1);
  assert(val.is_val());
  auto bv = val.get_val();
  auto num_bytes = bv->type->get_bv_width() / 8;
  assert(bv->type->get_bv_width() % 8 == 0);
  std::vector<ExprPtr> bytes;
  for (int i = num_bytes - 1; i >= 0; i--) {
    auto b = mk_expr_ptr(ExtractExpr, bv, i * 8, (i + 1) * 8);
    bytes.push_back(b);
  }
  auto old_f = content_f;
  Lambda::FuncT func = [off, old_f, num_bytes,
                        bytes](const OpApplyNode::ArgList &args) -> ExprPtr {
    auto result = old_f->func(args);
    for (int i = 0; i < num_bytes; i++) {
      auto off_i = mk_expr_ptr(AddExpr, {off, mk_expr_ptr(ConcreteBv, 64, i)});
      auto eq = mk_expr_ptr(EqExpr, {args[0], off_i});
      result = mk_expr_ptr(IteExpr, eq, bytes[i], result);
    }
    return result;
  };
  content_f = std::make_shared<Lambda>(content_f->type, func);
  modified = true;
}

RegValue Buffer::load(ExprPtr off, uint64_t size) const {
  if (cell_size > 1) {
    assert(size == cell_size);
    auto val = mk_expr_ptr(FuncApply, content_f, {off});
    return RegValue{val};
  }
  int num_bytes = size;
  std::vector<ExprPtr> bytes;
  ExprPtr ptr = off;
  for (int i = 0; i < num_bytes; i++) {
    auto b = mk_expr_ptr(FuncApply, content_f, {ptr});
    ptr = mk_expr_ptr(AddExpr, {ptr, mk_expr_ptr(ConcreteBv, 64, 1)});
    bytes.push_back(b);
  }
  std::reverse(bytes.begin(), bytes.end());
  return RegValue{mk_expr_ptr(ConcatExpr, bytes)};
}

void Buffer::store(ExprPtr off, RegValue val) {
  assert(val.is_val());
  auto bv = val.get_val();
  auto num_bytes = bv->type->get_bv_width() / 8;
  if (cell_size > 1) {
    assert(num_bytes == cell_size);
    auto old_f = content_f;
    Lambda::FuncT func = [off, old_f,
                          bv](const OpApplyNode::ArgList &args) -> ExprPtr {
      auto result = old_f->func(args);
      auto eq = mk_expr_ptr(EqExpr, {args[0], off});
      result = mk_expr_ptr(IteExpr, eq, bv, result);
      return result;
    };
    content_f = std::make_shared<Lambda>(content_f->type, func);
    return;
  }
  assert(bv->type->get_bv_width() % 8 == 0);
  std::vector<ExprPtr> bytes;
  for (int i = 0; i < num_bytes; i++) {
    auto b = mk_expr_ptr(ExtractExpr, bv, i * 8, (i + 1) * 8);
    bytes.push_back(b);
  }
  auto old_f = content_f;
  Lambda::FuncT func = [off, old_f, num_bytes,
                        bytes](const OpApplyNode::ArgList &args) -> ExprPtr {
    auto result = old_f->func(args);
    for (int i = 0; i < num_bytes; i++) {
      auto off_i = mk_expr_ptr(AddExpr, {off, mk_expr_ptr(ConcreteBv, 64, i)});
      auto eq = mk_expr_ptr(EqExpr, {args[0], off_i});
      result = mk_expr_ptr(IteExpr, eq, bytes[i], result);
    }
    return result;
  };
  content_f = std::make_shared<Lambda>(content_f->type, func);
  modified = true;
}

void Buffer::print(std::ostream &os) const { os << "(Buffer " << name << ")"; }
Symbolic::ExprPtr Buffer::equals(Buffer &other) const { return nullptr; }

ConcreteCacheBuffer::ConcreteCacheBuffer(const std::string &name)
    : Buffer(name) {}
ConcreteCacheBuffer::ConcreteCacheBuffer(const std::string &name, int size)
    : Buffer(name, size) {}

RegValue ConcreteCacheBuffer::load(Symbolic::ExprPtr off, uint64_t size) const {
  off = off->simplify();
  if (!off->is_symbolic()) {
    auto off_val =
        std::dynamic_pointer_cast<Symbolic::ConcreteBv>(off)->get_val();
    for (auto &r : cache) {
      if (r.off == off_val && r.size == size) {
        return r.val;
      }
    }
  }
  return Buffer::load(off, size);
}

void ConcreteCacheBuffer::store(Symbolic::ExprPtr off, RegValue val) {
  off = off->simplify();
  if (!off->is_symbolic() && val.is_val()) {
    auto off_val =
        std::dynamic_pointer_cast<Symbolic::ConcreteBv>(off)->get_val();

    std::vector<CacheRegion> new_cache;
    auto val_num_bits = val.get_val()->type->get_bv_width();
    assert(val_num_bits % 8 == 0);
    for (auto &r : cache) {
      if (off_val >= r.off + r.size || off_val + val_num_bits / 8 <= r.off) {
        new_cache.push_back(r);
      }
    }
    cache = new_cache;

    CacheRegion r;
    r.off = off_val;
    r.size = val_num_bits / 8;
    r.val = val;
    cache.push_back(r);
  } else {
    cache.clear();
  }
  return Buffer::store(off, val);
}

RegValue ConcreteCacheBuffer::load_be(Symbolic::ExprPtr off,
                                      uint64_t size) const {
  off = off->simplify();
  if (!off->is_symbolic()) {
    auto off_val =
        std::dynamic_pointer_cast<Symbolic::ConcreteBv>(off)->get_val();
    for (auto &r : cache) {
      if (r.off == off_val && r.size == size) {
        if (r.val.is_ptr()) {
          break;
        }
        return RegValue{endian_reverse(r.val.get_val())};
      }
    }
  }
  return Buffer::load(off, size);
}

void ConcreteCacheBuffer::store_be(Symbolic::ExprPtr off, RegValue val) {
  off = off->simplify();
  if (!off->is_symbolic() && val.is_val()) {
    auto off_val =
        std::dynamic_pointer_cast<Symbolic::ConcreteBv>(off)->get_val();

    std::vector<CacheRegion> new_cache;
    auto val_num_bits = val.get_val()->type->get_bv_width();
    assert(val_num_bits % 8 == 0);
    for (auto &r : cache) {
      if (off_val >= r.off + r.size || off_val + val_num_bits / 8 <= r.off) {
        new_cache.push_back(r);
      }
    }
    cache = new_cache;

    CacheRegion r;
    r.off = off_val;
    r.size = val_num_bits / 8;
    r.val = RegValue{endian_reverse(val.get_val())};
    cache.push_back(r);
  } else {
    std::cout << "dropping cache..." << std::endl;
    cache.clear();
  }
  return Buffer::store_be(off, val);
}

void ConcreteCacheBuffer::print(std::ostream &os) const {
  os << "(ConcreteCacheBuffer " << name << ")";
}

AbstractVector::AbstractVector(const std::string &name,
                               std::shared_ptr<Symbolic::Type> ele_type)
    : AbstractVector(name, ele_type,
                     mk_expr_ptr(SymbolicVar, std::make_shared<BitVecType>(64),
                                 name + "!len")) {}

AbstractVector::AbstractVector(const std::string &name,
                               std::shared_ptr<Symbolic::Type> ele_type,
                               uint64_t n)
    : AbstractVector(name, ele_type, mk_expr_ptr(ConcreteBv, 64, n)) {}

AbstractVector::AbstractVector(const std::string &name,
                               std::shared_ptr<Symbolic::Type> ele_type,
                               Symbolic::ExprPtr n) {
  auto bv_64 = std::make_shared<BitVecType>(64);
  std::vector<std::shared_ptr<ValType>> kt_l = {bv_64};
  auto e_type = std::dynamic_pointer_cast<ValType>(ele_type);
  auto ft = std::make_shared<UFType>(kt_l, e_type);
  auto uf = std::make_shared<SymbolicVar>(ft, name);
  Lambda::FuncT func = [uf](const OpApplyNode::ArgList &args) -> ExprPtr {
    return mk_expr_ptr(FuncApply, uf, args);
  };
  arr_f = std::make_shared<Lambda>(ft, func);
  n_elements = n;
  this->name = name;
  val_type = ele_type;
}

void AbstractVector::print(std::ostream &os) const {
  os << "(vector " << name << ")";
}

RegValue AbstractVector::handle_req(const std::string &method_name,
                                    const std::vector<RegValue> &args,
                                    std::shared_ptr<ExecutionState> ctx) {
  if (method_name == "get") {
  }
  return RegValue{nullptr};
}

bool AbstractVector::bound_check(Symbolic::ExprPtr idx) const {
  Z3Context ctx;
  auto lb = mk_expr_ptr(UleExpr, {mk_expr_ptr(ConcreteBv, 64, 0), idx});
  auto up = mk_expr_ptr(UltExpr, {idx, n_elements});
  auto bound = mk_expr_ptr(LAndExpr, {lb, up});
  auto expr = gen_z3_expr(ctx, bound).get_expr();
  z3::solver sol(ctx.ctx);
  sol.add(!expr);
  return sol.check() == z3::unsat;
}

Symbolic::ExprPtr AbstractVector::get(Symbolic::ExprPtr idx) const {
  using namespace Symbolic;
  assert(idx->type->is_bv_type() && idx->type->get_bv_width() == 64);
  return mk_expr_ptr(FuncApply, arr_f, {idx});
}

void AbstractVector::set(Symbolic::ExprPtr idx, Symbolic::ExprPtr val) {
  using namespace Symbolic;
  assert(idx->type->is_bv_type() && idx->type->get_bv_width() == 64);
  assert(val->type->equal_to(val_type));
  std::shared_ptr<Lambda> old_arr_f = arr_f;
  Lambda::FuncT func = [old_arr_f, val,
                        idx](const OpApplyNode::ArgList &args) -> ExprPtr {
    auto old_val = mk_expr_ptr(FuncApply, old_arr_f, args);
    auto eq = mk_expr_ptr(EqExpr, {idx, args[0]});
    return mk_expr_ptr(IteExpr, eq, val, old_val);
  };
  arr_f = std::make_shared<Lambda>(arr_f->type, func);
}

void AbstractVector::push_back(Symbolic::ExprPtr val) {
  using namespace Symbolic;
  assert(val->type->equal_to(val_type));
  auto idx = n_elements;
  n_elements =
      mk_expr_ptr(AddExpr, {n_elements, mk_expr_ptr(ConcreteBv, 64, 1)});
  modified = true;
  set(idx, val);
}

AbstractMap::AbstractMap(const std::string &name,
                         const Symbolic::PtrList<Symbolic::Type> &key_types,
                         const Symbolic::PtrList<Symbolic::Type> &val_types) {
  using namespace Symbolic;
  std::vector<std::shared_ptr<ValType>> key_type_list;
  for (auto t : key_types) {
    assert(t->is_val());
    key_type_list.push_back(std::dynamic_pointer_cast<ValType>(t));
  }
  auto bv_1 =
      std::dynamic_pointer_cast<ValType>(std::make_shared<BitVecType>(1));
  std::vector<std::shared_ptr<ValType>> val_type_list;
  for (auto t : val_types) {
    assert(t->is_val());
    val_type_list.push_back(std::dynamic_pointer_cast<ValType>(t));
  }

  auto ft = std::make_shared<UFType>(key_type_list, bv_1);
  auto uf = mk_expr_ptr(SymbolicVar, ft, name + "!contains");
  Lambda::FuncT func = [uf](const OpApplyNode::ArgList &args) -> ExprPtr {
    return mk_expr_ptr(FuncApply, uf, args);
  };
  contains_f = std::make_shared<Lambda>(ft, func);

  for (int i = 0; i < val_type_list.size(); i++) {
    auto ft = std::make_shared<UFType>(key_type_list, val_type_list[i]);
    auto uf = mk_expr_ptr(SymbolicVar, ft, name + "!val!" + std::to_string(i));
    Lambda::FuncT func = [uf](const OpApplyNode::ArgList &args) -> ExprPtr {
      return mk_expr_ptr(FuncApply, uf, args);
    };
    val_f.push_back(std::make_shared<Lambda>(ft, func));
  }
  this->name = name;
  this->key_types = key_types;
  this->val_types = val_types;
}

RegValue AbstractMap::handle_req(const std::string &method_name,
                                 const std::vector<RegValue> &args,
                                 std::shared_ptr<ExecutionState> ctx) {
  if (method_name == "get") {
  }
  return RegValue{nullptr};
}

Symbolic::ExprPtr
AbstractMap::contains(const Symbolic::OpApplyNode::ArgList &args) const {
  return mk_expr_ptr(FuncApply, contains_f, args);
}

std::vector<Symbolic::ExprPtr>
AbstractMap::get_vals(const Symbolic::OpApplyNode::ArgList &args) const {
  std::vector<Symbolic::ExprPtr> result;
  for (int i = 0; i < val_f.size(); i++) {
    result.push_back(mk_expr_ptr(FuncApply, val_f[i], args));
  }
  return result;
}

void AbstractMap::set_vals(const std::vector<Symbolic::ExprPtr> &args,
                           const std::vector<Symbolic::ExprPtr> &vals) {
  using namespace Symbolic;
  std::shared_ptr<Lambda> old_f = contains_f;
  std::vector<ExprPtr> keys = args;
  Lambda::FuncT func = [old_f, keys](const std::vector<ExprPtr> &a) -> ExprPtr {
    auto old_result = mk_expr_ptr(FuncApply, old_f, a);
    ExprPtr eq = nullptr;
    for (int i = 0; i < keys.size(); i++) {
      auto c = mk_expr_ptr(EqExpr, {keys[i], a[i]});
      if (eq == nullptr) {
        eq = c;
      } else {
        eq = mk_expr_ptr(LAndExpr, {eq, c});
      }
    }
    return mk_expr_ptr(IteExpr, eq, mk_expr_ptr(ConcreteBv, 1, 1), old_result);
  };
  contains_f = std::make_shared<Lambda>(old_f->type, func);

  for (int i = 0; i < vals.size(); i++) {
    ExprPtr v = vals[i];
    old_f = val_f[i];
    func = [old_f, v, keys](const std::vector<ExprPtr> &a) -> ExprPtr {
      auto old_result = mk_expr_ptr(FuncApply, old_f, a);
      ExprPtr eq = nullptr;
      for (int i = 0; i < keys.size(); i++) {
        auto c = mk_expr_ptr(EqExpr, {keys[i], a[i]});
        if (eq == nullptr) {
          eq = c;
        } else {
          eq = mk_expr_ptr(LAndExpr, {eq, c});
        }
      }
      return mk_expr_ptr(IteExpr, eq, v, old_result);
    };
    val_f[i] = std::make_shared<Lambda>(old_f->type, func);
  }
  modified = true;
}

void AbstractMap::delete_val(const Symbolic::OpApplyNode::ArgList &args) {
  using namespace Symbolic;
  std::shared_ptr<Lambda> old_f = contains_f;
  std::vector<ExprPtr> keys = args;
  Lambda::FuncT func = [old_f, keys](const std::vector<ExprPtr> &a) -> ExprPtr {
    auto old_result = mk_expr_ptr(FuncApply, old_f, a);
    ExprPtr eq = nullptr;
    for (int i = 0; i < keys.size(); i++) {
      auto c = mk_expr_ptr(EqExpr, {keys[i], a[i]});
      if (eq == nullptr) {
        eq = c;
      } else {
        eq = mk_expr_ptr(LAndExpr, {eq, c});
      }
    }
    return mk_expr_ptr(IteExpr, eq, mk_expr_ptr(ConcreteBv, 1, 0), old_result);
  };
  contains_f = std::make_shared<Lambda>(old_f->type, func);
  modified = true;
}

void AbstractMap::print(std::ostream &os) const {
  os << "(abstract-map " << name << ")";
}

Packet::Packet(const std::string &n, std::shared_ptr<ExecutionState> state) {
  name = n;
  content_buf_name = name + "!content";
  auto bv32 = std::make_shared<BitVecType>(32);
  len = mk_expr_ptr(SymbolicVar, bv32, name + "!len");

  auto pkt_content = std::make_shared<Buffer>(content_buf_name, 1600);
  state->objects.insert({content_buf_name, pkt_content});

  anno_buf_name = name + "!anno";
  auto anno_buf = std::make_shared<Buffer>(anno_buf_name, 128);
  state->objects.insert({anno_buf_name, anno_buf});
}

void Packet::print(std::ostream &os) const { os << "(Packet " << name << ")"; }

RegValue Packet::handle_req(const std::string &method_name,
                            const std::vector<RegValue> &args,
                            std::shared_ptr<ExecutionState> ctx) {
  assert(false && "unknown req");
}

AbstractObject::AbstractObject(const std::string &n) { name = n; }

RegValue AbstractObject::handle_req(const std::string &method_name,
                                    const std::vector<RegValue> &args,
                                    std::shared_ptr<ExecutionState> ctx) {
  throw "AbstractObject: handle_req not implemented";
}

std::shared_ptr<Pointee> AbstractObject::copy_self() const {
  auto result = std::make_shared<AbstractObject>(*this);
  return result;
}

void AbstractObject::print(std::ostream &os) const {
  os << "(abstract-object " << name << ")";
}

int AbstractObject::find_region(uint64_t off, Region &result) const {
  for (auto &r : regions) {
    if (off >= r.start_off && off < r.start_off + r.size) {
      result = r;
      return 0;
    }
  }
  return -1;
}

int AbstractObject::find_region(ExprPtr off, Region &r,
                                ExprPtr pre_cond) const {
  // TODO: fill in this
  return -1;
}

std::vector<AbstractObject::FindResultEntry>
AbstractObject::find_region(Symbolic::ExprPtr off) const {
  std::vector<FindResultEntry> result;
  for (auto &r : regions) {
    auto lb = mk_expr_ptr(UleExpr, {mk_concrete_bv(64, r.start_off), off});
    auto ub =
        mk_expr_ptr(UltExpr, {off, mk_concrete_bv(64, r.start_off + r.size)});
    auto in_range = mk_expr_ptr(AndExpr, {lb, ub});

    FindResultEntry e;
    e.pre_cond = in_range;
    e.region = r;
    result.push_back(e);
  }
  return result;
}

void AbstractObject::add_region(const Region &new_region) {
  // first make sure that there is no overlap
  auto r_start = new_region.start_off;
  auto r_end = r_start + new_region.size;

  for (auto &r : regions) {
    auto end = r.start_off + r.size;
    if (r_start < end && r.start_off < r_end) {
      assert(false && "inserting overlapping region");
    }
  }

  regions.push_back(new_region);
}

void AbstractObject::add_ptr_at(std::shared_ptr<ExecutionState> s,
                                const SymPointer &ptr, uint64_t off) {
  auto ptr_store = std::make_shared<PointerStore>(
      s->name_gen(ptr.pointer_base + "_ptr_store"), ptr);

  s->add_pointee(ptr_store);

  Region r;
  r.type = Region::T::INLINED;
  r.start_off = off;
  r.size = 8;
  r.ptr = SymPointer(ptr_store->name);

  add_region(r);
}

void AbstractObject::add_obj_ptr_at(std::shared_ptr<ExecutionState> s,
                                    std::shared_ptr<Pointee> obj,
                                    uint64_t off) {
  SymPointer obj_ptr(obj->name);
  add_ptr_at(s, obj_ptr, off);
}
