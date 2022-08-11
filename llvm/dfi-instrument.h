#ifndef _HQ_LLVM_DFI_INSTRUMENT_H_
#define _HQ_LLVM_DFI_INSTRUMENT_H_

#include "llvm/IR/PassManager.h"
#include "llvm/PassRegistry.h"

#include "config.h"

namespace llvm {
void initializeDFIInstrumentLegacyPassPass(PassRegistry &);

struct DFIInstrumentLegacyPass : public ModulePass {
    static char ID;

    DFIInstrumentLegacyPass() : ModulePass(ID) {}
    void getAnalysisUsage(AnalysisUsage &AU) const override;
    bool runOnModule(Module &M) override;
}; // end of struct DFIInstrumentLegacyPass

struct DFIInstrumentPass : public PassInfoMixin<DFIInstrumentPass> {
    DFIInstrumentPass() {}
    static void create(ModulePassManager &MPM);
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
}; // end of struct DFIInstrumentPass
}; // namespace llvm

#endif /* _HQ_LLVM_DFI_INSTRUMENT_H_ */
