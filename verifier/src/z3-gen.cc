#include "z3-gen.h"
#include "utils.h"

namespace Symbolic {

z3::expr bool_to_bv1(z3::context &ctx, z3::expr &v) {
  return z3::ite(v, ctx.bv_val(1, 1), ctx.bv_val(0, 1));
}

z3::expr bv1_to_bool(z3::expr &v) { return v == 1; }

bool Z3Expr::is_bool() const {
  return this->is_expr() && std::get<z3::expr>(content).is_bool();
}

bool Z3Expr::is_expr() const {
  return std::holds_alternative<z3::expr>(content);
}

bool Z3Expr::is_func() const {
  return std::holds_alternative<z3::func_decl>(content);
}

z3::expr Z3Expr::get_expr() { return std::get<z3::expr>(content); }

z3::expr Z3Expr::get_bool() {
  auto e = std::get<z3::expr>(content);
  if (e.is_bv()) {
    return bv1_to_bool(std::get<z3::expr>(content));
  } else {
    return e;
  }
}

z3::func_decl Z3Expr::get_func() { return std::get<z3::func_decl>(content); }

#define DECL_VISITOR(T) virtual void visit_expr(T &e) override;

class Z3GenVisitor : public ExprVisitor {
public:
  Z3Context &my_ctx;
  z3::context &ctx;
  std::variant<z3::expr, z3::func_decl, int> result;

  Z3GenVisitor(Z3Context &c) : my_ctx(c), ctx(my_ctx.ctx), result(0) {}

  DECL_VISITOR(Expr);
  DECL_VISITOR(Lambda);
  DECL_VISITOR(ConcreteBv);
  DECL_VISITOR(SymbolicVar);

  DECL_VISITOR(AddExpr);
  DECL_VISITOR(SubExpr);
  DECL_VISITOR(MulExpr);
  DECL_VISITOR(DivExpr);
  DECL_VISITOR(ModExpr);
  DECL_VISITOR(UDivExpr);
  DECL_VISITOR(UModExpr);

  DECL_VISITOR(LAndExpr);
  DECL_VISITOR(LOrExpr);
  DECL_VISITOR(LXorExpr);
  DECL_VISITOR(LNotExpr);
  DECL_VISITOR(ImpliesExpr);

  DECL_VISITOR(AndExpr);
  DECL_VISITOR(OrExpr);
  DECL_VISITOR(XorExpr);
  DECL_VISITOR(NotExpr);
  DECL_VISITOR(LshExpr);
  DECL_VISITOR(LRshExpr);
  DECL_VISITOR(ARshExpr);

  DECL_VISITOR(EqExpr);
  DECL_VISITOR(NeqExpr);
  DECL_VISITOR(LeExpr);
  DECL_VISITOR(LtExpr);
  DECL_VISITOR(GeExpr);
  DECL_VISITOR(GtExpr);
  DECL_VISITOR(UleExpr);
  DECL_VISITOR(UltExpr);
  DECL_VISITOR(UgeExpr);
  DECL_VISITOR(UgtExpr);

  DECL_VISITOR(ExtractExpr);
  DECL_VISITOR(SExtExpr);
  DECL_VISITOR(UExtExpr);

  DECL_VISITOR(IteExpr);
  DECL_VISITOR(FuncApply);
  DECL_VISITOR(ConcatExpr);

  DECL_VISITOR(ForallExpr);
  DECL_VISITOR(ExistsExpr);
};

#undef DECL_VISITOR
#define VISITOR_IMPL(T) void Z3GenVisitor::visit_expr(T &e)
#define LOAD_BIN_OPRAND                                                        \
  auto &args = e.args_;                                                        \
  assert(args.size() == 2);                                                    \
  auto a1 = gen_z3_expr(my_ctx, args[0]);                                      \
  auto a2 = gen_z3_expr(my_ctx, args[1])

VISITOR_IMPL(Expr) {}
VISITOR_IMPL(Lambda) { throw "could not gen z3 expr from lambda"; }
VISITOR_IMPL(ConcreteBv) {
  auto t = e.type;
  result = ctx.bv_val(e.get_val(), t->get_bv_width());
}
VISITOR_IMPL(SymbolicVar) {
  auto t = e.type;
  if (t->is_bv_type()) {
    result = ctx.bv_const(e.name.c_str(), t->get_bv_width());
  } else if (t->is_func_type()) {
    auto t = std::dynamic_pointer_cast<UFType>(e.type);
    z3::sort_vector key_sorts(ctx);
    for (int i = 0; i < t->key_types.size(); i++) {
      auto s = ctx.bv_sort(t->key_types[i]->get_bv_width());
      key_sorts.push_back(s);
    }
    auto val_sort = ctx.bv_sort(t->val_type->get_bv_width());
    result = ctx.function(e.name.c_str(), key_sorts, val_sort);
  }
}

VISITOR_IMPL(AddExpr) {
  LOAD_BIN_OPRAND;
  result = a1.get_expr() + a2.get_expr();
}
VISITOR_IMPL(SubExpr) {
  LOAD_BIN_OPRAND;
  result = a1.get_expr() - a2.get_expr();
}
VISITOR_IMPL(MulExpr) {
  LOAD_BIN_OPRAND;
  result = a1.get_expr() * a2.get_expr();
}
VISITOR_IMPL(DivExpr) {
  LOAD_BIN_OPRAND;
  result = a1.get_expr() / a2.get_expr();
}
VISITOR_IMPL(ModExpr) {
  LOAD_BIN_OPRAND;
  result = a1.get_expr() % a2.get_expr();
}
VISITOR_IMPL(UDivExpr) {
  LOAD_BIN_OPRAND;
  result = z3::udiv(a1.get_expr(), a2.get_expr());
}
VISITOR_IMPL(UModExpr) {
  LOAD_BIN_OPRAND;
  result = z3::urem(a1.get_expr(), a2.get_expr());
}

VISITOR_IMPL(LAndExpr) {
  LOAD_BIN_OPRAND;
  result = a1.get_bool() && a2.get_bool();
}
VISITOR_IMPL(LOrExpr) {
  LOAD_BIN_OPRAND;
  result = a1.get_bool() || a2.get_bool();
}
VISITOR_IMPL(LXorExpr) {
  LOAD_BIN_OPRAND;
  result = a1.get_bool() ^ a2.get_bool();
}
VISITOR_IMPL(ImpliesExpr) {
  LOAD_BIN_OPRAND;
  result = z3::implies(a1.get_bool(), a2.get_bool());
}

VISITOR_IMPL(AndExpr) {
  LOAD_BIN_OPRAND;
  if (e.args_[0]->type->get_bv_width() == 1) {
    result = a1.get_bool() && a2.get_bool();
  } else {
    result = a1.get_expr() & a2.get_expr();
  }
}
VISITOR_IMPL(OrExpr) {
  LOAD_BIN_OPRAND;
  if (e.args_[0]->type->get_bv_width() == 1) {
    result = a1.get_bool() || a2.get_bool();
  } else {
    result = a1.get_expr() | a2.get_expr();
  }
}
VISITOR_IMPL(XorExpr) {
  LOAD_BIN_OPRAND;
  if (e.args_[0]->type->get_bv_width() == 1) {
    // need to use the C version instead
    auto a = a1.get_bool();
    auto b = a2.get_bool();
    check_context(a, b);
    assert(a.is_bool() && b.is_bool());
    result = z3::expr(a.ctx(), Z3_mk_xor(a.ctx(), a, b));
  } else {
    result = a1.get_expr() ^ a2.get_expr();
  }
}
VISITOR_IMPL(LshExpr) {
  LOAD_BIN_OPRAND;
  result = z3::shl(a1.get_expr(), a2.get_expr());
}
VISITOR_IMPL(LRshExpr) {
  LOAD_BIN_OPRAND;
  result = z3::lshr(a1.get_expr(), a2.get_expr());
}
VISITOR_IMPL(ARshExpr) {
  LOAD_BIN_OPRAND;
  result = z3::ashr(a1.get_expr(), a2.get_expr());
}

VISITOR_IMPL(EqExpr) {
  LOAD_BIN_OPRAND;
  result = (a1.get_expr() == a2.get_expr());
}
VISITOR_IMPL(NeqExpr) {
  LOAD_BIN_OPRAND;
  result = (a1.get_expr() != a2.get_expr());
}
VISITOR_IMPL(LeExpr) {
  LOAD_BIN_OPRAND;
  result = (a1.get_expr() <= a2.get_expr());
}
VISITOR_IMPL(LtExpr) {
  LOAD_BIN_OPRAND;
  result = (a1.get_expr() < a2.get_expr());
}
VISITOR_IMPL(GeExpr) {
  LOAD_BIN_OPRAND;
  result = (a1.get_expr() >= a2.get_expr());
}
VISITOR_IMPL(GtExpr) {
  LOAD_BIN_OPRAND;
  result = (a1.get_expr() > a2.get_expr());
}
VISITOR_IMPL(UleExpr) {
  LOAD_BIN_OPRAND;
  result = z3::ule(a1.get_expr(), a2.get_expr());
}
VISITOR_IMPL(UltExpr) {
  LOAD_BIN_OPRAND;
  result = z3::ult(a1.get_expr(), a2.get_expr());
}
VISITOR_IMPL(UgeExpr) {
  LOAD_BIN_OPRAND;
  result = z3::uge(a1.get_expr(), a2.get_expr());
}
VISITOR_IMPL(UgtExpr) {
  LOAD_BIN_OPRAND;
  result = z3::ugt(a1.get_expr(), a2.get_expr());
}
VISITOR_IMPL(LNotExpr) {
  auto a = gen_z3_expr(my_ctx, e.args_[0]);
  result = !a.get_bool();
}
VISITOR_IMPL(NotExpr) {
  auto a = gen_z3_expr(my_ctx, e.args_[0]);
  if (e.args_[0]->type->get_bv_width() == 1) {
    result = !a.get_bool();
  } else {
    result = ~a.get_expr();
  }
}
VISITOR_IMPL(ExtractExpr) {
  auto a = gen_z3_expr(my_ctx, e.v);
  result = a.get_expr().extract(e.to - 1, e.from);
}
VISITOR_IMPL(SExtExpr) {
  auto a = gen_z3_expr(my_ctx, e.v);
  auto bw = e.v->type->get_bv_width();
  result = z3::sext(a.get_expr(), e.to - bw);
}
VISITOR_IMPL(UExtExpr) {
  auto a = gen_z3_expr(my_ctx, e.v);
  auto bw = e.v->type->get_bv_width();
  result = z3::zext(a.get_expr(), e.to - bw);
}
VISITOR_IMPL(IteExpr) {
  auto c = gen_z3_expr(my_ctx, e.cond).get_bool();
  auto t = gen_z3_expr(my_ctx, e.t_val).get_expr();
  auto f = gen_z3_expr(my_ctx, e.f_val).get_expr();
  result = z3::ite(c, t, f);
}
VISITOR_IMPL(FuncApply) {
  auto f = e.func;
  if (f->is_symbolic()) {
    auto func = gen_z3_expr(my_ctx, f).get_func();
    z3::expr_vector args(my_ctx.ctx);
    for (int i = 0; i < e.args_.size(); i++) {
      args.push_back(gen_z3_expr(my_ctx, e.args_[i]).get_expr());
    }
    result = func(args);
  } else {
    // func is lambda;
    auto func = std::dynamic_pointer_cast<Lambda>(f)->func;
    auto val = func(e.args_);
    result = gen_z3_expr(my_ctx, val).get_expr();
  }
}
VISITOR_IMPL(ConcatExpr) {
  z3::expr_vector bv_vec(my_ctx.ctx);
  for (int i = 0; i < e.args_.size(); i++) {
    auto expr = gen_z3_expr(my_ctx, e.args_[i]).get_expr();
    bv_vec.push_back(expr);
  }
  result = z3::concat(bv_vec);
}

VISITOR_IMPL(ForallExpr) {
  z3::expr_vector var_vec(my_ctx.ctx);
  for (int i = 0; i < e.vars.size(); i++) {
    auto expr = gen_z3_expr(my_ctx, e.vars[i]).get_expr();
    var_vec.push_back(expr);
  }
  auto cond = gen_z3_expr(my_ctx, e.cond).get_bool();
  result = z3::forall(var_vec, cond);
}

VISITOR_IMPL(ExistsExpr) {
  z3::expr_vector var_vec(my_ctx.ctx);
  for (int i = 0; i < e.vars.size(); i++) {
    auto expr = gen_z3_expr(my_ctx, e.vars[i]).get_expr();
    var_vec.push_back(expr);
  }
  auto cond = gen_z3_expr(my_ctx, e.cond).get_bool();
  result = z3::exists(var_vec, cond);
}

#undef VISITOR_IMPL

Z3Expr gen_z3_expr(Z3Context &ctx, ExprPtr expr) {
  auto uuid = expr->get_uuid();
  if (ctx.cache_.find(uuid) != ctx.cache_.end()) {
    return ctx.cache_[uuid];
  }
  if (expr->is_var()) {
    auto e = std::dynamic_pointer_cast<SymbolicVar>(expr);
    if (ctx.var_cache_.find(e->name) != ctx.var_cache_.end()) {
      return ctx.var_cache_[e->name];
    }
  }
  Z3GenVisitor visitor(ctx);
  visitor.visit(*expr);
  Z3Expr result;
  result.content = visitor.result;
  ctx.cache_[uuid] = result;
  if (expr->is_var()) {
    auto e = std::dynamic_pointer_cast<SymbolicVar>(expr);
    ctx.var_cache_[e->name] = result;
  }
  return result;
}

bool verify_with_z3(Z3Context &ctx, ExprPtr pre_cond, ExprPtr target,
                    bool do_fork) {
  std::function f = [&]() -> std::string {
    if (pre_cond == nullptr) {
      pre_cond = mk_concrete_bv(1, 1);
    }
    if (target == nullptr) {
      target = mk_concrete_bv(1, 0);
    }

    assert(pre_cond->type->get_bv_width() == 1);
    assert(target->type->get_bv_width() == 1);

    auto pre = gen_z3_expr(ctx, pre_cond).get_bool();
    auto post = gen_z3_expr(ctx, target).get_bool();
    z3::solver sol(ctx.ctx);
    sol.add(pre);
    sol.add(!post);
    if (sol.check() == z3::unsat) {
      return "verified";
    } else {
      return "unverified";
    }
  };
  if (do_fork) {
    SubProcessFunc remote_f(f);
    return remote_f() == "verified";
  } else {
    return f() == "verified";
  }
}

void print_expr_z3(ExprPtr expr, std::ostream &os) {
  Z3Context ctx;
  auto e = gen_z3_expr(ctx, expr);
  os << e.get_expr().simplify();
}
} // namespace Symbolic
