#pragma once

#include <boost/functional/hash.hpp>
#include <variant>
#include <z3++.h>

#include "symbolic-expr.h"

namespace Symbolic {
struct Z3Expr {
  std::variant<z3::expr, z3::func_decl, int> content;

  bool is_expr() const;
  bool is_func() const;
  bool is_bool() const;
  z3::expr get_expr();
  z3::expr get_bool();
  z3::func_decl get_func();

  Z3Expr() : content(0) {}
};
struct Z3Context {
  z3::context ctx;
  std::unordered_map<boost::uuids::uuid, Z3Expr,
                     boost::hash<boost::uuids::uuid>>
      cache_;
  std::unordered_map<std::string, Z3Expr> var_cache_;
};

Z3Expr gen_z3_expr(Z3Context &ctx, ExprPtr expr);

bool verify_with_z3(Z3Context &ctx, ExprPtr pre_cond, ExprPtr target,
                    bool do_fork = false);

void print_expr_z3(ExprPtr expr, std::ostream &os);
} // namespace Symbolic
