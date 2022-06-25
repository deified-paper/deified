#ifndef _DFI_LLVM_INIT_H_
#define _DFI_LLVM_INIT_H_

#include "llvm/Support/CommandLine.h"

#include <string>

// Shared configuration flags
extern llvm::cl::opt<bool> RunDFI;

extern llvm::cl::opt<std::string> InlinePath;

#endif /* _DFI_LLVM_INIT_H_ */
