#include "llvm-helpers.h"
#include "llvm-incl.h"
#include "utils.h"

std::string indent(int lvl) {
  std::string result = "";
  for (int i = 0; i < lvl; i++) {
    result = result + "  ";
  }
  return result;
}

void print_element_state(llvm::Module *m, llvm::Type *t, int off, int lvl = 0,
                         bool include_header = true, bool no_newline = false) {
  auto dl = std::make_shared<llvm::DataLayout>(m);
  if (include_header) {
    std::cout << indent(lvl) << off << " | ";
  }
  if (t->isPointerTy()) {
    auto et = t->getPointerElementType();
    std::cout << "ptr<" << get_type_name(et) << ">";
  } else if (t->isStructTy()) {
    llvm::StructType *st = llvm::dyn_cast<llvm::StructType>(t);
    auto sl = dl->getStructLayout(st);
    std::cout << "[STRUCT]" << std::endl;
    for (auto i = 0; i < st->getNumElements(); i++) {
      auto field_t = st->getElementType(i);
      auto field_off = sl->getElementOffset(i);
      print_element_state(m, field_t, off + field_off, lvl + 1, true, false);
    }
    no_newline = true;
  } else if (t->isArrayTy()) {
    auto num_element = t->getArrayNumElements();
    auto et = t->getArrayElementType();
    print_element_state(m, et, off, lvl, false, true);
    std::cout << " * " << num_element;
  } else if (t->isIntegerTy()) {
    auto size = dl->getTypeStoreSize(t);
    std::cout << "Integer(" << size << ")";
  }

  if (!no_newline) {
    std::cout << std::endl;
  }
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " "
              << "<ir-file> <class-name>" << std::endl;
    return -1;
  }

  const std::string ir_filename = std::string(argv[1]);
  const std::string class_name = std::string(argv[2]);

  llvm::LLVMContext ctx;
  llvm::SMDiagnostic err;
  auto module = llvm::parseIRFile(ir_filename, err, ctx);

  if (module == nullptr) {
    std::cerr << "failed to parse IR file" << std::endl;
    std::cerr << err.getMessage().str() << std::endl;
    return -1;
  }

  auto structs = module->getIdentifiedStructTypes();
  llvm::StructType *element_t = nullptr;
  for (auto &s : structs) {
    if (s->getName() == "class." + class_name) {
      element_t = s;
      break;
    }
    if (s->getName() == "struct." + class_name) {
      element_t = s;
      break;
    }
  }

  if (element_t == nullptr) {
    std::cout << "Error: could not find element class definition" << std::endl;
    std::cout << "Found classes: " << std::endl;
    for (auto &s : structs) {
      std::cout << s->getName().str() << std::endl;
    }
    return -1;
  }

  // print element state recursively (with offsets)
  print_element_state(module.get(), element_t, 0);
  return 0;
}
