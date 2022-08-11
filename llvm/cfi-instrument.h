#ifndef _CFI_LLVM_CFI_INSTRUMENT_H_
#define _CFI_LLVM_CFI_INSTRUMENT_H_

#include "llvm/IR/PassManager.h"
#include "llvm/PassRegistry.h"

#include "config.h"

namespace llvm {
void initializeCFIInstrumentLegacyPassPass(PassRegistry &);

struct CFIInstrumentLegacyPass : public ModulePass {
    static char ID;
    bool LowerOnly;

    CFIInstrumentLegacyPass(bool _LO = false)
        : ModulePass(ID), LowerOnly(_LO) {}
    void getAnalysisUsage(AnalysisUsage &AU) const override;
    bool runOnModule(Module &M) override;
}; // end of struct CFIInstrumentLegacyPass

struct CFIInstrumentPass : public PassInfoMixin<CFIInstrumentPass> {
    bool LowerOnly;

    CFIInstrumentPass(bool _LO) : LowerOnly(_LO) {}
    static void create(ModulePassManager &MPM, bool LowerOnly = false);
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
}; // end of struct CFIInstrumentPass
}; // namespace llvm

#endif /* _CFI_LLVM_CFI_INSTRUMENT_H_ */
