#include <cassert>
#include <cstdio>
#include <functional>
#include <iostream>
#include <sstream>

#include "symbolic-expr.h"

namespace Symbolic {

void ExprVisitor::visit(Expr &expr) { expr.accept(*this); }

void BitVecType::print(std::ostream &os) const {
  os << "BitVecType(" << bitwidth << ")";
}

bool BitVecType::equal_to(std::shared_ptr<Type> t) const {
  if (t->is_bv_type()) {
    auto w = t->get_bv_width();
    return w == bitwidth;
  }

  return false;
}

void UFType::print(std::ostream &os) const {
  os << "Function(";
  for (int i = 0; i < key_types.size(); i++) {
    key_types[i]->print(os);
    os << " -> ";
  }
  val_type->print(os);
  os << ")";
}

bool UFType::equal_to(std::shared_ptr<Type> t) const {
  if (t->is_func_type()) {
    auto ft = std::dynamic_pointer_cast<UFType>(t);
    for (int i = 0; i < key_types.size(); i++) {
      if (!ft->key_types[i]->equal_to(key_types[i])) {
        return false;
      }
    }

    return val_type->equal_to(ft->val_type);
  }

  return false;
}

Expr::Expr() : uuid(boost::uuids::random_generator()()) {}

OpApplyNode::OpApplyNode(const ArgList &args) : args_(args) {
  is_symbolic_ = false;
  for (auto &a : args) {
    if (a->is_symbolic()) {
      is_symbolic_ = true;
      break;
    }
  }
  is_symbolic_ = true;
}

void OpApplyNode::type_check(const PtrList<Type> &types) {
  if (types.size() != args_.size()) {
    std::stringstream ss;
    ss << "Arglist size mismatch: ";
    ss << "Expecting " << types.size() << " "
       << "got " << args_.size();
    throw TypeCheckError{ss.str()};
  }

  for (int i = 0; i < types.size(); i++) {
    if (!args_[i]->type->equal_to(types[i])) {
      std::stringstream ss;
      ss << "Arg #" << i << " : Type mismatch: ";
      ss << "Expecting ";
      types[i]->print(ss);
      ss << " "
         << "got ";
      args_[i]->type->print(ss);
      throw TypeCheckError{ss.str()};
    }
  }
}

OpApplyNode::ArgList OpApplyNode::simplify_args() const {
  ArgList result;

  for (int i = 0; i < args_.size(); i++) {
    result.push_back(args_[i]->simplify());
  }

  return result;
}

Lambda::Lambda(std::shared_ptr<Type> func_type, FuncT f) {
  if (!func_type->is_func_type()) {
    throw TypeCheckError{"Expecting function type"};
  }
  std::shared_ptr<UFType> ft = std::dynamic_pointer_cast<UFType>(func_type);
  for (auto kt : ft->key_types) {
    if (!kt->is_val()) {
      throw TypeCheckError{"Function Args should be value type"};
    }
  }
  if (!ft->val_type->is_val()) {
    throw TypeCheckError{"Function should return value type"};
  }
  type = func_type;
  func = f;
}

Lambda::Lambda(const PtrList<Type> &arg_t, std::shared_ptr<Type> ret_t,
               FuncT f) {
  std::vector<std::shared_ptr<ValType>> arg_t_list;
  std::shared_ptr<ValType> vt;
  for (auto t : arg_t) {
    if (!t->is_val()) {
      throw TypeCheckError{"Function Args should be value type"};
    }
    arg_t_list.push_back(std::dynamic_pointer_cast<ValType>(t));
  }

  if (!ret_t->is_val()) {
    throw TypeCheckError{"Function return type shoud be value type "};
  } else {
    vt = std::dynamic_pointer_cast<ValType>(ret_t);
  }

  auto t = std::make_shared<UFType>(arg_t_list, vt);

  type = t;
  func = f;
}

FuncApply::FuncApply(ExprPtr f, const ArgList &args) : OpApplyNode(args) {
  if (!f->type->is_func_type()) {
    throw TypeCheckError{"FuncApply expect function type"};
  }
  auto ft = std::dynamic_pointer_cast<UFType>(f->type);
  PtrList<Type> kt_list;
  for (auto t : ft->key_types) {
    kt_list.push_back(std::dynamic_pointer_cast<Type>(t));
  }
  type_check(kt_list);
  type = ft->val_type;
  func = f;
}

BvBinOpExpr::BvBinOpExpr(const ArgList &args) : OpApplyNode(args) {
  if (args_.size() != 2) {
    throw TypeCheckError{"Bin op requires two args"};
  }
  if (!args_[0]->type->equal_to(args_[1]->type)) {
    throw TypeCheckError{"Bin op args type mismatch"};
  }
  if (!args_[0]->type->is_bv_type()) {
    throw TypeCheckError{"Expecting BitVec type"};
  }
  auto t = std::make_shared<BitVecType>();
  t->bitwidth = args_[0]->type->get_bv_width();
  type = std::dynamic_pointer_cast<Type>(t);
}

ExprPtr BvBinOpExpr::simplify() {
  auto args = simplify_args();
  args_ = args;
  for (auto &a : args) {
    if (a->is_symbolic()) {
      return shared_from_this();
    }
  }
  auto a1 = std::dynamic_pointer_cast<ConcreteBv>(args[0])->get_val();
  auto a2 = std::dynamic_pointer_cast<ConcreteBv>(args[1])->get_val();
  return this->concrete_binop(a1, a2);
}

BvBinPredExpr::BvBinPredExpr(const ArgList &args) : OpApplyNode(args) {
  if (args_.size() != 2) {
    throw TypeCheckError{"Bin op requires two args"};
  }
  if (!args_[0]->type->equal_to(args_[1]->type)) {
    throw TypeCheckError{"Bin op args type mismatch"};
  }
  if (!args_[0]->type->is_bv_type()) {
    throw TypeCheckError{"Expecting BitVec type"};
  }
  auto t = std::make_shared<BitVecType>();
  t->bitwidth = 1;
  type = std::dynamic_pointer_cast<Type>(t);
}

ExprPtr BvBinPredExpr::simplify() {
  auto args = simplify_args();
  args_ = args;
  for (auto &a : args) {
    if (a->is_symbolic()) {
      return shared_from_this();
    }
  }
  auto a1 = std::dynamic_pointer_cast<ConcreteBv>(args[0])->get_val();
  auto a2 = std::dynamic_pointer_cast<ConcreteBv>(args[1])->get_val();
  return this->concrete_binop(a1, a2);
}

#define BV_BIN_OP_CONSTR(class_name)                                           \
  class_name::class_name(const ArgList &args) : BvBinOpExpr(args) {}

#define BV_BIN_PRED_CONSTR(class_name)                                         \
  class_name::class_name(const ArgList &args) : BvBinPredExpr(args) {}

#define BV_BIN_OP_CONCRETE(class_name, expr)                                   \
  ExprPtr class_name::concrete_binop(uint64_t a1, uint64_t a2) {               \
    uint64_t val = (uint64_t)(expr);                                           \
    auto bw = this->type->get_bv_width();                                      \
    uint64_t mask = (1UL << bw) - 1;                                           \
    if (bw == 64) {                                                            \
      mask = (uint64_t)-1L;                                                    \
    }                                                                          \
    if (bw > 64) {                                                             \
      return shared_from_this();                                               \
    }                                                                          \
    val = val & mask;                                                          \
    return mk_expr_ptr(ConcreteBv, this->type->get_bv_width(), val);           \
  }

BV_BIN_OP_CONSTR(AddExpr);
BV_BIN_OP_CONSTR(SubExpr);
BV_BIN_OP_CONSTR(MulExpr);
BV_BIN_OP_CONSTR(DivExpr);
BV_BIN_OP_CONSTR(ModExpr);

BV_BIN_OP_CONSTR(UDivExpr);
BV_BIN_OP_CONSTR(UModExpr);

BV_BIN_OP_CONSTR(LAndExpr);
BV_BIN_OP_CONSTR(LOrExpr);
BV_BIN_OP_CONSTR(LXorExpr);
BV_BIN_OP_CONSTR(ImpliesExpr);

BV_BIN_OP_CONSTR(AndExpr);
BV_BIN_OP_CONSTR(OrExpr);
BV_BIN_OP_CONSTR(XorExpr);
BV_BIN_OP_CONSTR(LshExpr);
BV_BIN_OP_CONSTR(LRshExpr);
BV_BIN_OP_CONSTR(ARshExpr);

BV_BIN_PRED_CONSTR(EqExpr);
BV_BIN_PRED_CONSTR(NeqExpr);
BV_BIN_PRED_CONSTR(LeExpr);
BV_BIN_PRED_CONSTR(LtExpr);
BV_BIN_PRED_CONSTR(GeExpr);
BV_BIN_PRED_CONSTR(GtExpr);
BV_BIN_PRED_CONSTR(UleExpr);
BV_BIN_PRED_CONSTR(UltExpr);
BV_BIN_PRED_CONSTR(UgeExpr);
BV_BIN_PRED_CONSTR(UgtExpr);

BV_BIN_OP_CONCRETE(AddExpr, a1 + a2);
BV_BIN_OP_CONCRETE(SubExpr, a1 - a2);
BV_BIN_OP_CONCRETE(MulExpr, a1 *a2);
BV_BIN_OP_CONCRETE(DivExpr, (int64_t)a1 / (int64_t)a2);
BV_BIN_OP_CONCRETE(ModExpr, (int64_t)a1 % (int64_t)a2);

BV_BIN_OP_CONCRETE(UDivExpr, a1 / a2);
BV_BIN_OP_CONCRETE(UModExpr, a1 % a2);

BV_BIN_OP_CONCRETE(LAndExpr, (a1 != 0) & (a2 != 0));
BV_BIN_OP_CONCRETE(LOrExpr, (a1 != 0) | (a2 != 0));
BV_BIN_OP_CONCRETE(LXorExpr, (a1 != 0) ^ (a1 != 0));
BV_BIN_OP_CONCRETE(ImpliesExpr, !(a1 != 0) | (a2 != 0));

BV_BIN_OP_CONCRETE(AndExpr, a1 &a2);
BV_BIN_OP_CONCRETE(OrExpr, a1 | a2);
BV_BIN_OP_CONCRETE(XorExpr, a1 ^ a2);
BV_BIN_OP_CONCRETE(LshExpr, a1 << a2);
BV_BIN_OP_CONCRETE(LRshExpr, a1 >> a2);
BV_BIN_OP_CONCRETE(ARshExpr, (int64_t)a1 >> a2);

BV_BIN_OP_CONCRETE(EqExpr, a1 == a2);
BV_BIN_OP_CONCRETE(NeqExpr, a1 != a2);
BV_BIN_OP_CONCRETE(LeExpr, (int64_t)a1 <= (int64_t)a2);
BV_BIN_OP_CONCRETE(LtExpr, (int64_t)a1 < (int64_t)a2);
BV_BIN_OP_CONCRETE(GeExpr, (int64_t)a1 >= (int64_t)a2);
BV_BIN_OP_CONCRETE(GtExpr, (int64_t)a1 > (int64_t)a2);
BV_BIN_OP_CONCRETE(UleExpr, a1 <= a2);
BV_BIN_OP_CONCRETE(UltExpr, a1 < a2);
BV_BIN_OP_CONCRETE(UgeExpr, a1 >= a2);
BV_BIN_OP_CONCRETE(UgtExpr, a1 > a2);

ConcatExpr::ConcatExpr(const ArgList &args) : OpApplyNode(args) {
  int bw = 0;
  for (int i = 0; i < args.size(); i++) {
    if (!args[i]->type->is_bv_type()) {
      throw TypeCheckError{"concat expects bitvec"};
    }
    bw += args[i]->type->get_bv_width();
  }
  type = std::dynamic_pointer_cast<Type>(std::make_shared<BitVecType>(bw));
}

LNotExpr::LNotExpr(ExprPtr a) : OpApplyNode({a}) { type = a->type; }

NotExpr::NotExpr(ExprPtr a) : OpApplyNode({a}) { type = a->type; }

ExtractExpr::ExtractExpr(ExprPtr e, int start, int end)
    : v(e), from(start), to(end) {
  if (!v->type->is_bv_type()) {
    throw TypeCheckError{"Not BitVec"};
  }

  if (to <= from || v->type->get_bv_width() < to) {
    throw TypeCheckError{"BV size error"};
  }

  type =
      std::dynamic_pointer_cast<Type>(std::make_shared<BitVecType>(to - from));
}

SExtExpr::SExtExpr(ExprPtr e, int t) : v(e), to(t) {
  type = std::dynamic_pointer_cast<Type>(std::make_shared<BitVecType>(to));
}

UExtExpr::UExtExpr(ExprPtr e, int t) : v(e), to(t) {
  type = std::dynamic_pointer_cast<Type>(std::make_shared<BitVecType>(to));
}

IteExpr::IteExpr(ExprPtr c, ExprPtr t, ExprPtr f)
    : cond(c), t_val(t), f_val(f) {
  if (!t_val->type->equal_to(f_val->type)) {
    throw TypeCheckError{"Ite type mismatch"};
  }
  type = t_val->type;
}

std::shared_ptr<Expr> IteExpr::simplify() {
  auto c = cond->simplify();
  auto t = t_val->simplify();
  auto f = f_val->simplify();

  if (c->is_symbolic()) {
    cond = c;
    t_val = t;
    f_val = f;
    return shared_from_this();
  } else {
    // concrete condition
    auto concrete_cond = std::dynamic_pointer_cast<ConcreteBv>(c);
    if (concrete_cond->get_val() == 1) {
      return t;
    } else {
      return f;
    }
  }
}

ForallExpr::ForallExpr(const std::vector<ExprPtr> &vs, ExprPtr c) {
  vars = vs;
  cond = c;

  for (auto &v : vs) {
    assert(v->type->is_bv_type());
  }
  assert(c->type->is_bv_type());
  assert(c->type->get_bv_width() == 1);

  auto t = std::make_shared<BitVecType>();
  t->bitwidth = 1;
  type = std::dynamic_pointer_cast<Type>(t);
}

std::shared_ptr<Expr> ForallExpr::simplify() {
  cond = cond->simplify();
  return shared_from_this();
}

ExistsExpr::ExistsExpr(const std::vector<ExprPtr> &vs, ExprPtr c) {
  vars = vs;
  cond = c;

  for (auto &v : vs) {
    assert(v->type->is_bv_type());
  }
  assert(c->type->is_bv_type());
  assert(c->type->get_bv_width() == 1);

  auto t = std::make_shared<BitVecType>();
  t->bitwidth = 1;
  type = std::dynamic_pointer_cast<Type>(t);
}

std::shared_ptr<Expr> ExistsExpr::simplify() {
  cond = cond->simplify();
  return shared_from_this();
}

#undef BV_BIN_PRED_CONSTR
#undef BV_BIN_OP_CONSTR

ExprPtr endian_reverse(ExprPtr val) {
  auto num_bits = val->type->get_bv_width();
  assert(num_bits % 8 == 0);
  auto num_bytes = num_bits / 8;

  std::vector<ExprPtr> bytes;
  for (int i = 0; i < num_bytes; i++) {
    bytes.push_back(mk_expr_ptr(ExtractExpr, val, i * 8, (i + 1) * 8));
  }

  ExprPtr result = nullptr;
  for (int i = 0; i < num_bytes; i++) {
    if (result == nullptr) {
      result = bytes[i];
    } else {
      result = mk_expr_ptr(ConcatExpr, {result, bytes[i]});
    }
  }
  return result->simplify();
}

uint64_t get_concrete_val(ExprPtr v) {
  assert(!v->is_symbolic());
  return std::dynamic_pointer_cast<ConcreteBv>(v)->get_val();
}

#define DEF_PRINT(T) virtual void visit_expr(T &e) override

// just print type
#define DEF_NAIVE_PRINT(T)                                                     \
  virtual void visit_expr(T &e) override { os << "(some " #T " )"; }

// OpApplyNode print
#define DEF_OPAPPLY_PRINT(T)                                                   \
  virtual void visit_expr(T &e) override {                                     \
    os << "(" #T " ";                                                          \
    for (auto &a : e.args_) {                                                  \
      print_expr(a, os);                                                       \
      os << " ";                                                               \
    }                                                                          \
  }

class ExprPrintVisitor : public ExprVisitor {
public:
  ExprPrintVisitor(std::ostream &_os) : os(_os) {}

  DEF_NAIVE_PRINT(Expr);
  DEF_NAIVE_PRINT(Lambda);
  DEF_PRINT(ConcreteBv) { os << e.get_val(); }
  DEF_NAIVE_PRINT(SymbolicVar);

  DEF_OPAPPLY_PRINT(AddExpr);
  DEF_OPAPPLY_PRINT(SubExpr);
  DEF_OPAPPLY_PRINT(MulExpr);
  DEF_OPAPPLY_PRINT(DivExpr);
  DEF_OPAPPLY_PRINT(ModExpr);
  DEF_OPAPPLY_PRINT(UDivExpr);
  DEF_OPAPPLY_PRINT(UModExpr);

  DEF_OPAPPLY_PRINT(LAndExpr);
  DEF_OPAPPLY_PRINT(LOrExpr);
  DEF_OPAPPLY_PRINT(LXorExpr);
  DEF_OPAPPLY_PRINT(LNotExpr);
  DEF_OPAPPLY_PRINT(ImpliesExpr);

  DEF_OPAPPLY_PRINT(AndExpr);
  DEF_OPAPPLY_PRINT(OrExpr);
  DEF_OPAPPLY_PRINT(XorExpr);
  DEF_OPAPPLY_PRINT(NotExpr);
  DEF_OPAPPLY_PRINT(LshExpr);
  DEF_OPAPPLY_PRINT(LRshExpr);
  DEF_OPAPPLY_PRINT(ARshExpr);

  DEF_OPAPPLY_PRINT(EqExpr);
  DEF_OPAPPLY_PRINT(NeqExpr);
  DEF_OPAPPLY_PRINT(LeExpr);
  DEF_OPAPPLY_PRINT(LtExpr);
  DEF_OPAPPLY_PRINT(GeExpr);
  DEF_OPAPPLY_PRINT(GtExpr);
  DEF_OPAPPLY_PRINT(UleExpr);
  DEF_OPAPPLY_PRINT(UltExpr);
  DEF_OPAPPLY_PRINT(UgeExpr);
  DEF_OPAPPLY_PRINT(UgtExpr);

  DEF_NAIVE_PRINT(ExtractExpr);
  DEF_NAIVE_PRINT(SExtExpr);
  DEF_NAIVE_PRINT(UExtExpr);

  DEF_NAIVE_PRINT(IteExpr);
  DEF_NAIVE_PRINT(FuncApply);
  DEF_OPAPPLY_PRINT(ConcatExpr);

  DEF_NAIVE_PRINT(ForallExpr);
  DEF_NAIVE_PRINT(ExistsExpr);

  std::ostream &os;
};

#undef DEF_PRINT
#undef DEF_NAIVE_PRINT
#undef DEF_OPAPPLY_PRINT

void print_expr(ExprPtr expr, std::ostream &os) {
  ExprPrintVisitor v(os);
  v.visit(*expr);
}

} // namespace Symbolic

std::shared_ptr<Symbolic::Type> mk_bv_type(int bitwidth) {
  return std::make_shared<Symbolic::BitVecType>(bitwidth);
}

std::shared_ptr<Symbolic::Expr> mk_bv_var(int bitwidth,
                                          const std::string &name) {
  auto t = mk_bv_type(bitwidth);
  return mk_expr_ptr(SymbolicVar, t, name);
}
