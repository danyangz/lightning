#pragma once

#include <unordered_map>
#include <unordered_set>

#include "executor.h"
#include "symbolic-expr.h"

struct PointeeAccessError {
  std::string msg;
};

enum class PointeeType {
  PointerStore,
  Vector,
  HashMap,
  Buffer,
  Packet,
  Object,
  Invalid,
};

std::ostream &operator<<(std::ostream &os, const PointeeType &t);

class Pointee {
public:
  virtual bool is_abstract() const { return false; }
  virtual bool is_plain_mem() const { return false; }
  virtual RegValue handle_req(const std::string &method_name,
                              const std::vector<RegValue> &args,
                              std::shared_ptr<ExecutionState> ctx) = 0;
  virtual RegValue load(Symbolic::ExprPtr off, uint64_t size) const = 0;
  virtual void store(Symbolic::ExprPtr off, RegValue val) = 0;

  virtual std::shared_ptr<Pointee> copy_self() const = 0;

  virtual void print(std::ostream &os) const = 0;
  virtual PointeeType type() const { return PointeeType::Invalid; }

  std::string name;

  bool modified = false;
};

// a buffer that stores a single pointer
class PointerStore : public Pointee {
public:
  PointerStore(const std::string &n) : PointerStore(n, 1) {}
  PointerStore(const std::string &n, const SymPointer &p) {
    name = n;
    ptrs.push_back(p);
    num_ptrs = 1;
  }
  PointerStore(const std::string &n, int num_ptrs) {
    name = n;
    num_ptrs = num_ptrs;
    for (int i = 0; i < num_ptrs; i++) {
      SymPointer ptr("", nullptr, mk_bv_var(64, name + std::to_string(i)));
      ptrs.push_back(ptr);
    }
  }
  virtual bool is_abstract() const { return true; }
  virtual bool is_plain_mem() const { return false; }
  virtual RegValue handle_req(const std::string &method_name,
                              const std::vector<RegValue> &args,
                              std::shared_ptr<ExecutionState> ctx) {
    throw "pointer store cannot handle request";
  }

  virtual RegValue load(Symbolic::ExprPtr off, uint64_t size) const;
  virtual void store(Symbolic::ExprPtr off, RegValue val);

  virtual std::shared_ptr<Pointee> copy_self() const {
    return std::make_shared<PointerStore>(*this);
  }

  virtual void print(std::ostream &os) const;
  virtual PointeeType type() const { return PointeeType::PointerStore; }

  SymPointer load_ptr(int idx = 0) const { return ptrs[idx]; }
  void store_ptr(const SymPointer &p, int idx = 0) { ptrs[idx] = p; }

  struct MultiPtrEntry {
    Symbolic::ExprPtr pre_cond;
    SymPointer ptr;
  };
  using MultiPtr = std::vector<MultiPtrEntry>;
  MultiPtr load_ptr(Symbolic::ExprPtr off) const;

  std::vector<SymPointer> ptrs;

  int num_ptrs;
};

class AbstractFunc {
public:
  virtual bool match(const std::string &fn) const = 0;

  using ResultT = std::vector<std::shared_ptr<ExecutionState>>;
  virtual ResultT call(const std::string &func_name,
                       const std::vector<RegValue> &params,
                       std::shared_ptr<ExecutionState> state,
                       const std::string &dst_reg) = 0;
};

class Inaccessible : public Pointee {
public:
  Inaccessible(const std::string &name);

  virtual RegValue handle_req(const std::string &method_name,
                              const std::vector<RegValue> &args,
                              std::shared_ptr<ExecutionState> ctx) override {
    throw ExecError{"Inaccessible"};
  }
  virtual RegValue load(Symbolic::ExprPtr off, uint64_t size) const override {
    throw ExecError{"Inaccessible"};
  }
  virtual void store(Symbolic::ExprPtr off, RegValue val) override {
    throw ExecError{"Inaccessible"};
  }

  virtual std::shared_ptr<Pointee> copy_self() const override {
    auto ptr = std::make_shared<Inaccessible>(*this);
    return std::dynamic_pointer_cast<Pointee>(ptr);
  }

  virtual void print(std::ostream &os) const override;
};

class Buffer : public Pointee {
public:
  Buffer(const std::string &name);
  Buffer(const std::string &name, int size, int cell_size = 1);
  virtual bool is_plain_mem() const override { return true; }

  virtual RegValue handle_req(const std::string &method_name,
                              const std::vector<RegValue> &args,
                              std::shared_ptr<ExecutionState> ctx) override {
    throw ExecError{"Buffer could not handle request"};
  }
  virtual RegValue load(Symbolic::ExprPtr off, uint64_t size) const override;
  virtual void store(Symbolic::ExprPtr off, RegValue val) override;

  RegValue load_be(Symbolic::ExprPtr off, uint64_t size) const;
  void store_be(Symbolic::ExprPtr off, RegValue val);

  virtual std::shared_ptr<Pointee> copy_self() const override {
    auto result = std::make_shared<Buffer>(*this);
    return std::dynamic_pointer_cast<Pointee>(result);
  }
  virtual void print(std::ostream &os) const override;
  Symbolic::ExprPtr equals(Buffer &buf) const;

  virtual PointeeType type() const override { return PointeeType::Buffer; }

  std::shared_ptr<Symbolic::Lambda> content_f;
  bool sized;
  int size;

  int cell_size = 1;

  bool have_write_back = false;
  std::function<void(std::shared_ptr<Buffer>, std::shared_ptr<ExecutionState>)>
      write_back_fn;
};

class ConcreteCacheBuffer : public Buffer {
public:
  ConcreteCacheBuffer(const std::string &name);
  ConcreteCacheBuffer(const std::string &name, int size);
  virtual bool is_plain_mem() const override { return true; }

  virtual RegValue handle_req(const std::string &method_name,
                              const std::vector<RegValue> &args,
                              std::shared_ptr<ExecutionState> ctx) override {
    throw ExecError{"Buffer could not handle request"};
  }
  virtual RegValue load(Symbolic::ExprPtr off, uint64_t size) const override;
  virtual void store(Symbolic::ExprPtr off, RegValue val) override;

  RegValue load_be(Symbolic::ExprPtr off, uint64_t size) const;
  void store_be(Symbolic::ExprPtr off, RegValue val);

  virtual std::shared_ptr<Pointee> copy_self() const override {
    auto result = std::make_shared<ConcreteCacheBuffer>(*this);
    return std::dynamic_pointer_cast<Pointee>(result);
  }
  virtual void print(std::ostream &os) const override;
  Symbolic::ExprPtr equals(ConcreteCacheBuffer &buf) const { return nullptr; }

  virtual PointeeType type() const override { return PointeeType::Buffer; }

  struct CacheRegion {
    uint64_t off;
    size_t size;
    RegValue val;
  };

  std::vector<CacheRegion> cache;

  std::shared_ptr<Symbolic::Lambda> content_f;
  bool sized;
  int size;

  bool have_write_back = false;
  std::function<void(std::shared_ptr<Buffer>, std::shared_ptr<ExecutionState>)>
      write_back_fn;
};

class AbstractType : public Pointee {
public:
  virtual bool is_abstract() const override { return true; }
  virtual RegValue load(Symbolic::ExprPtr off, uint64_t size) const override {
    throw ExecError{
        "Could not perform load / store on abstract data structure"};
  }
  virtual void store(Symbolic::ExprPtr off, RegValue val) override {
    throw ExecError{
        "Could not perform load / store on abstract data structure"};
  }
};

class AbstractVector : public AbstractType {
public:
  AbstractVector(const std::string &name,
                 std::shared_ptr<Symbolic::Type> ele_type);
  AbstractVector(const std::string &name,
                 std::shared_ptr<Symbolic::Type> ele_type,
                 Symbolic::ExprPtr n_elements);
  AbstractVector(const std::string &name,
                 std::shared_ptr<Symbolic::Type> ele_type, uint64_t n_elements);
  virtual RegValue handle_req(const std::string &method_name,
                              const std::vector<RegValue> &args,
                              std::shared_ptr<ExecutionState> ctx) override;

  virtual std::shared_ptr<Pointee> copy_self() const override {
    auto result = std::make_shared<AbstractVector>(*this);
    return std::dynamic_pointer_cast<Pointee>(result);
  }

  virtual void print(std::ostream &os) const override;

  std::shared_ptr<Symbolic::Expr> get(Symbolic::ExprPtr idx) const;
  void set(Symbolic::ExprPtr idx, Symbolic::ExprPtr val);
  void push_back(Symbolic::ExprPtr val);

  bool bound_check(Symbolic::ExprPtr idx) const;
  virtual PointeeType type() const override { return PointeeType::Vector; }
  std::shared_ptr<Symbolic::Lambda> arr_f;
  std::shared_ptr<Symbolic::Type> val_type;
  Symbolic::ExprPtr n_elements;
};

class AbstractMap : public AbstractType {
public:
  AbstractMap(const std::string &name,
              const Symbolic::PtrList<Symbolic::Type> &key_types,
              const Symbolic::PtrList<Symbolic::Type> &val_types);
  virtual RegValue handle_req(const std::string &method_name,
                              const std::vector<RegValue> &args,
                              std::shared_ptr<ExecutionState> ctx) override;

  virtual std::shared_ptr<Pointee> copy_self() const override {
    auto result = std::make_shared<AbstractMap>(*this);
    return std::dynamic_pointer_cast<Pointee>(result);
  }

  std::vector<std::shared_ptr<Symbolic::Type>> key_types;
  std::vector<std::shared_ptr<Symbolic::Type>> val_types;
  std::shared_ptr<Symbolic::Lambda> contains_f;
  std::vector<std::shared_ptr<Symbolic::Lambda>> val_f;

  Symbolic::ExprPtr contains(const Symbolic::OpApplyNode::ArgList &args) const;
  std::vector<Symbolic::ExprPtr>
  get_vals(const Symbolic::OpApplyNode::ArgList &args) const;
  void set_vals(const std::vector<Symbolic::ExprPtr> &args,
                const std::vector<Symbolic::ExprPtr> &vals);
  void delete_val(const Symbolic::OpApplyNode::ArgList &args);

  virtual void print(std::ostream &os) const override;
  virtual PointeeType type() const override { return PointeeType::HashMap; }
};

class Packet : public AbstractType {
public:
  Packet(const std::string &name, std::shared_ptr<ExecutionState> state);

  virtual RegValue handle_req(const std::string &method_name,
                              const std::vector<RegValue> &args,
                              std::shared_ptr<ExecutionState> ctx);

  virtual std::shared_ptr<Pointee> copy_self() const {
    auto ptr = std::make_shared<Packet>(*this);
    return std::dynamic_pointer_cast<Pointee>(ptr);
  }

  virtual void print(std::ostream &os) const;
  virtual PointeeType type() const { return PointeeType::Packet; }

  std::string anno_buf_name;
  Symbolic::ExprPtr len;
  std::string content_buf_name;
};

// This is essentially a buffer with certain regions blocked
class AbstractObject : public AbstractType {
public:
  AbstractObject(const std::string &name);
  virtual RegValue handle_req(const std::string &method_name,
                              const std::vector<RegValue> &args,
                              std::shared_ptr<ExecutionState> ctx) override;

  virtual std::shared_ptr<Pointee> copy_self() const override;

  virtual void print(std::ostream &os) const override;
  virtual PointeeType type() const override { return PointeeType::Object; }

  struct Region {
    enum class T {
      INVALID,
      INLINED, // inlined means that this object is a part of the object,
               // instead of a pointer
    };

    T type;
    uint64_t start_off;
    uint64_t size;

    SymPointer ptr;

    Region() {}
    Region(T t, uint64_t start, uint64_t sz, SymPointer p)
        : type(t), start_off(start), size(sz), ptr(p) {}
  };

  /* return value:
   * 0  : found a region
   * -1 : not accessible region
   */
  int find_region(uint64_t off, Region &r) const;
  int find_region(Symbolic::ExprPtr off, Region &r,
                  Symbolic::ExprPtr pre_cond = nullptr) const;

  struct FindResultEntry {
    Symbolic::ExprPtr pre_cond;
    Region region;
  };

  std::vector<FindResultEntry> find_region(Symbolic::ExprPtr off) const;

  void add_region(const Region &r);

  void add_ptr_at(std::shared_ptr<ExecutionState> s, const SymPointer &ptr,
                  uint64_t off);
  void add_obj_ptr_at(std::shared_ptr<ExecutionState> s,
                      std::shared_ptr<Pointee> obj, uint64_t off);

protected:
  std::vector<Region> regions;
};
