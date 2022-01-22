#pragma once

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <functional>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace Symbolic {

#define DEF_TYPE_PREDICATE_DEFAULT(predicate_name)                             \
  virtual bool predicate_name() const { return false; }

struct TypeCheckError {
  std::string msg;
};

class Type {
public:
  virtual bool is_val() const = 0;
  virtual bool equal_to(std::shared_ptr<Type> t) const = 0;
  virtual void print(std::ostream &os) const = 0;
  virtual int get_bv_width() const { throw TypeCheckError{"not a bit vector"}; }
  virtual bool is_bv_type() const { return false; }
  virtual bool is_func_type() const { return false; }
};

class ValType : public Type {
public:
  enum class T {
    BITVEC,
  };

  T type;

  virtual bool is_val() const override { return true; }
};

class BitVecType : public ValType {
public:
  int bitwidth;

  virtual int get_bv_width() const override { return bitwidth; }

  virtual bool is_bv_type() const override { return true; }

  virtual void print(std::ostream &os) const override;
  virtual bool equal_to(std::shared_ptr<Type> t) const override;

  BitVecType() : bitwidth(0) {}
  BitVecType(int bw) : bitwidth(bw) {}
};

class UFType : public Type {
public:
  std::vector<std::shared_ptr<ValType>> key_types;
  std::shared_ptr<ValType> val_type;

  UFType(const std::vector<std::shared_ptr<ValType>> &kts,
         std::shared_ptr<ValType> vt)
      : key_types(kts), val_type(vt) {}

  virtual bool is_val() const override { return false; }

  virtual bool is_func_type() const override { return true; }

  virtual void print(std::ostream &os) const override;
  virtual bool equal_to(std::shared_ptr<Type> t) const override;
};

class Expr;
class Lambda;
class ConcreteBv;
class SymbolicVar;
class AddExpr;
class SubExpr;
class MulExpr;
class DivExpr;
class ModExpr;
class UDivExpr;
class UModExpr;

class LAndExpr;
class LOrExpr;
class LXorExpr;
class LNotExpr;
class ImpliesExpr;

class AndExpr;
class OrExpr;
class XorExpr;
class NotExpr;
class LshExpr;
class LRshExpr;
class ARshExpr;

class EqExpr;
class NeqExpr;
class LeExpr;
class LtExpr;
class GeExpr;
class GtExpr;
class UleExpr;
class UltExpr;
class UgeExpr;
class UgtExpr;

class ExtractExpr;
class SExtExpr;
class UExtExpr;

class IteExpr;
class FuncApply;
class ConcatExpr;

class ForallExpr;
class ExistsExpr;

#define DECLARE_EXPR_VISITOR(t)                                                \
  virtual void visit_expr(t &expr) { this->visit_expr(*(Expr *)&expr); }

class ExprVisitor {
public:
  virtual void visit(Expr &expr);

  virtual void visit_expr(Expr &e) {}
  DECLARE_EXPR_VISITOR(Lambda);
  DECLARE_EXPR_VISITOR(ConcreteBv);
  DECLARE_EXPR_VISITOR(SymbolicVar);

  DECLARE_EXPR_VISITOR(AddExpr);
  DECLARE_EXPR_VISITOR(SubExpr);
  DECLARE_EXPR_VISITOR(MulExpr);
  DECLARE_EXPR_VISITOR(DivExpr);
  DECLARE_EXPR_VISITOR(ModExpr);
  DECLARE_EXPR_VISITOR(UDivExpr);
  DECLARE_EXPR_VISITOR(UModExpr);

  DECLARE_EXPR_VISITOR(LAndExpr);
  DECLARE_EXPR_VISITOR(LOrExpr);
  DECLARE_EXPR_VISITOR(LXorExpr);
  DECLARE_EXPR_VISITOR(LNotExpr);
  DECLARE_EXPR_VISITOR(ImpliesExpr);

  DECLARE_EXPR_VISITOR(AndExpr);
  DECLARE_EXPR_VISITOR(OrExpr);
  DECLARE_EXPR_VISITOR(XorExpr);
  DECLARE_EXPR_VISITOR(NotExpr);
  DECLARE_EXPR_VISITOR(LshExpr);
  DECLARE_EXPR_VISITOR(LRshExpr);
  DECLARE_EXPR_VISITOR(ARshExpr);

  DECLARE_EXPR_VISITOR(EqExpr);
  DECLARE_EXPR_VISITOR(NeqExpr);
  DECLARE_EXPR_VISITOR(LeExpr);
  DECLARE_EXPR_VISITOR(LtExpr);
  DECLARE_EXPR_VISITOR(GeExpr);
  DECLARE_EXPR_VISITOR(GtExpr);
  DECLARE_EXPR_VISITOR(UleExpr);
  DECLARE_EXPR_VISITOR(UltExpr);
  DECLARE_EXPR_VISITOR(UgeExpr);
  DECLARE_EXPR_VISITOR(UgtExpr);

  DECLARE_EXPR_VISITOR(ExtractExpr);
  DECLARE_EXPR_VISITOR(SExtExpr);
  DECLARE_EXPR_VISITOR(UExtExpr);

  DECLARE_EXPR_VISITOR(IteExpr);
  DECLARE_EXPR_VISITOR(FuncApply);
  DECLARE_EXPR_VISITOR(ConcatExpr);

  DECLARE_EXPR_VISITOR(ForallExpr);
  DECLARE_EXPR_VISITOR(ExistsExpr);
};

using ExprPtr = std::shared_ptr<Expr>;

#define VISITOR_ACCEPT                                                         \
  virtual void accept(ExprVisitor &v) override { v.visit_expr(*this); }

class Expr : public std::enable_shared_from_this<Expr> {
public:
  std::shared_ptr<Type> type;
  DEF_TYPE_PREDICATE_DEFAULT(is_symbolic);
  DEF_TYPE_PREDICATE_DEFAULT(is_var);

  Expr();

  virtual std::shared_ptr<Expr> simplify() { return shared_from_this(); }

  virtual void accept(ExprVisitor &v) { v.visit_expr(*this); }

  boost::uuids::uuid get_uuid() const { return uuid; }

protected:
  boost::uuids::uuid uuid;
};

template <typename T> using PtrList = std::vector<std::shared_ptr<T>>;

class OpApplyNode : public Expr {
public:
  using ArgList = PtrList<Expr>;

  OpApplyNode(const ArgList &args);

  void type_check(const PtrList<Type> &types);

  virtual bool is_symbolic() const override { return is_symbolic_; }

  ArgList simplify_args() const;

public:
  ArgList args_;
  bool is_symbolic_;
};

class ConcreteVal : public Expr {
public:
};

class Lambda : public Expr {
public:
  using FuncT = std::function<ExprPtr(OpApplyNode::ArgList)>;
  FuncT func;

  Lambda(std::shared_ptr<Type> func_type, FuncT func);

  Lambda(const PtrList<Type> &arg_t, std::shared_ptr<Type> ret_t, FuncT func);
  VISITOR_ACCEPT;
};

class ConcreteBv : public ConcreteVal {
public:
  ConcreteBv(int bv_size, uint64_t val) {
    auto t = std::make_shared<BitVecType>();
    t->bitwidth = bv_size;
    type = std::dynamic_pointer_cast<Type>(t);
    val_ = val;
  }

  uint64_t get_val() const { return val_; }

  VISITOR_ACCEPT;

protected:
  uint64_t val_;
};

class SymbolicVar : public Expr {
public:
  SymbolicVar(std::shared_ptr<Type> t, const std::string &n) : name(n) {
    type = t;
  }
  virtual bool is_symbolic() const override { return true; }
  virtual bool is_var() const override { return true; }

  VISITOR_ACCEPT;

  std::string name;
};

class FuncApply : public OpApplyNode {
public:
  FuncApply(ExprPtr func, const ArgList &args);
  VISITOR_ACCEPT;

  ExprPtr func;
};

class BvBinOpExpr : public OpApplyNode {
public:
  BvBinOpExpr(const ArgList &args);
  virtual ExprPtr simplify() override;
  virtual ExprPtr concrete_binop(uint64_t a1, uint64_t a2) {
    return shared_from_this();
  }
};

class BvBinPredExpr : public OpApplyNode {
public:
  BvBinPredExpr(const ArgList &args);
  virtual ExprPtr simplify() override;
  virtual ExprPtr concrete_binop(uint64_t a1, uint64_t a2) {
    return shared_from_this();
  }
};

#define DECLARE_OP(class_name)                                                 \
  class class_name : public BvBinOpExpr {                                      \
  public:                                                                      \
    class_name(const ArgList &args);                                           \
    VISITOR_ACCEPT;                                                            \
    virtual ExprPtr concrete_binop(uint64_t a1, uint64_t a2) override;         \
  }

#define DECLARE_PRED(class_name)                                               \
  class class_name : public BvBinPredExpr {                                    \
  public:                                                                      \
    class_name(const ArgList &args);                                           \
    VISITOR_ACCEPT;                                                            \
    virtual ExprPtr concrete_binop(uint64_t a1, uint64_t a2) override;         \
  }

DECLARE_OP(AddExpr);
DECLARE_OP(SubExpr);
DECLARE_OP(MulExpr);
DECLARE_OP(DivExpr);
DECLARE_OP(ModExpr);
DECLARE_OP(UDivExpr);
DECLARE_OP(UModExpr);

DECLARE_OP(LAndExpr);
DECLARE_OP(LOrExpr);
DECLARE_OP(LXorExpr);
DECLARE_OP(ImpliesExpr);

DECLARE_OP(AndExpr);
DECLARE_OP(OrExpr);
DECLARE_OP(XorExpr);
DECLARE_OP(LshExpr);
DECLARE_OP(LRshExpr);
DECLARE_OP(ARshExpr);

DECLARE_PRED(EqExpr);
DECLARE_PRED(NeqExpr);
DECLARE_PRED(LeExpr);
DECLARE_PRED(LtExpr);
DECLARE_PRED(GeExpr);
DECLARE_PRED(GtExpr);
DECLARE_PRED(UleExpr);
DECLARE_PRED(UltExpr);
DECLARE_PRED(UgeExpr);
DECLARE_PRED(UgtExpr);

class ConcatExpr : public OpApplyNode {
public:
  ConcatExpr(const ArgList &args);
  VISITOR_ACCEPT;
};
class LNotExpr : public OpApplyNode {
public:
  LNotExpr(ExprPtr e);
  VISITOR_ACCEPT;
};

class NotExpr : public OpApplyNode {
public:
  NotExpr(ExprPtr e);
  VISITOR_ACCEPT;
};

class ExtractExpr : public Expr {
public:
  ExtractExpr(ExprPtr e, int start, int end);
  VISITOR_ACCEPT;

  virtual bool is_symbolic() const override { return true; }

  ExprPtr v;
  int from, to;
};

class SExtExpr : public Expr {
public:
  SExtExpr(ExprPtr e, int to);
  VISITOR_ACCEPT;

  virtual bool is_symbolic() const override { return true; }

  ExprPtr v;
  int to;
};

class UExtExpr : public Expr {
public:
  UExtExpr(ExprPtr e, int to);
  VISITOR_ACCEPT;

  virtual bool is_symbolic() const override { return true; }

  ExprPtr v;
  int to;
};

class IteExpr : public Expr {
public:
  IteExpr(ExprPtr cond, ExprPtr t, ExprPtr f);
  VISITOR_ACCEPT;
  virtual std::shared_ptr<Expr> simplify() override;

  virtual bool is_symbolic() const override { return true; }

  ExprPtr cond;
  ExprPtr t_val;
  ExprPtr f_val;
};

class ForallExpr : public Expr {
public:
  ForallExpr(const std::vector<ExprPtr> &vars, ExprPtr cond);
  VISITOR_ACCEPT;
  virtual std::shared_ptr<Expr> simplify() override;

  virtual bool is_symbolic() const override { return true; }

  std::vector<ExprPtr> vars;
  ExprPtr cond;
};

class ExistsExpr : public Expr {
public:
  ExistsExpr(const std::vector<ExprPtr> &vars, ExprPtr cond);
  VISITOR_ACCEPT;
  virtual std::shared_ptr<Expr> simplify() override;

  virtual bool is_symbolic() const override { return true; }

  std::vector<ExprPtr> vars;
  ExprPtr cond;
};

#undef DECLARE_PRED
#undef DECLARE_OP

ExprPtr endian_reverse(ExprPtr val);

uint64_t get_concrete_val(ExprPtr v);

void print_expr(ExprPtr expr, std::ostream &os);
} // namespace Symbolic

std::shared_ptr<Symbolic::Type> mk_bv_type(int bitwidth);

#define mk_expr_ptr(T, ...)                                                    \
  std::dynamic_pointer_cast<::Symbolic::Expr>(                                 \
      std::shared_ptr<::Symbolic::T>(new ::Symbolic::T(__VA_ARGS__)))

std::shared_ptr<Symbolic::Expr> mk_bv_var(int bitwidth,
                                          const std::string &name);
#define mk_concrete_bv(bw, n) mk_expr_ptr(ConcreteBv, bw, n)
