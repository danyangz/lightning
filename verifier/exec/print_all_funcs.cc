#include <iostream>

#include "llvm-helpers.h"

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cout << "Usage " << argv[0] << " <ll-file>" << std::endl;
    return -1;
  }
  auto fn = std::string(argv[1]);
  llvm::LLVMContext ctx;
  llvm::SMDiagnostic err;

  auto m = llvm::parseIRFile(fn, err, ctx);
  if (m == nullptr) {
    std::cerr << err.getMessage().str() << std::endl;
    assert(false && "parseIRFile failed");
  }

  for (auto iter = m->begin(); iter != m->end(); iter++) {
    if (iter->isDeclaration()) {
      continue;
    }
    auto fn = iter->getName().str();
    std::cout << fn << std::endl;
  }
  return 0;
}
