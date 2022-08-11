#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/IPO/AlwaysInliner.h"
#include "llvm/Transforms/IPO/GlobalDCE.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/Mem2Reg.h"

#ifndef NDEBUG
#include "llvm/IR/Verifier.h"
#endif

#include <unordered_map>
#include <unordered_set>

#include "config.h"
#include "runtime.h"

#include "dfi-init.h"
#include "dfi-instrument.h"
#include "utils.h"

#define DEBUG_TYPE "dfi-instrument"

using namespace llvm;

static cl::opt<bool>
    LibraryFunctions("dfi-library-memcpy",
                     cl::desc("Instrument memcpy (default = true)"),
                     cl::init(true));

static cl::opt<bool>
    UseAliasAnalysis("hq-alias-analysis",
                     cl::desc("Use alias analysis results to analysis function "
                              "behavior (default = true)"),
                     cl::init(true));
// Ensure statistics are defined even in release mode
#if !defined(NDEBUG) || defined(LLVM_ENABLE_STATS)
STATISTIC(NumLoads, "Number of instrumented reads");
STATISTIC(NumStores, "Number of instrumented writes");
STATISTIC(NumInvals, "Number of instrumented invalidates");
STATISTIC(NumObjReads, "Number of instrumented object reads");
STATISTIC(NumObjWrites, "Number of instrumented object writes");
STATISTIC(NumObjInvals, "Number of instrumented object invalidates");
STATISTIC(NumCopy, "Number of pointer copies");
#else
static unsigned int NumLoads = 0, NumStores = 0, NumInvals = 0, NumObjReads = 0,
                    NumObjWrites = 0, NumObjInvals = 0, NumCopy = 0;
#endif /* !NDEBUG || LLVM_ENABLE_STATS */

using AliasAnalysisCallback = function_ref<AliasAnalysis *(Function &F)>;

/* Visitor for modifying instructions */
struct InstrumentVisitor : public InstVisitor<InstrumentVisitor> {
    const DataLayout *DL;
    IRBuilder<> IRB;
    AliasAnalysisCallback &AACB;
    IntegerType *I64Ty;
    FunctionCallee OCF, ODF, OIF, PCF, PDF, PIF, PMCF;

    AliasAnalysis *currentAAResult;
    // Track lifetime of stack-allocated variables with annotated subfields
    std::unordered_map<const AllocaInst *, SmallSet<Value *, 1>> InstrAllocas;
    // Avoid duplicate instrumentation for llvm.memcpy.*(), which can be
    // handled either through VisitAnnotatedPointer or VisitIntrinsicInst
    std::unordered_set<const IntrinsicInst *> InstrMemCpys;
    SmallVector<Instruction *, 4> Remove;

    InstrumentVisitor(LLVMContext &C, AliasAnalysisCallback &_AACB)
        : IRB(C), AACB(_AACB) {}

    // Override hierarchy to perform post-visit modifications
    void visit(Module &M) {
        visitModule(M);
        InstVisitor::visit(M.begin(), M.end());

        InstrMemCpys.clear();
    }

    void visit(Function &F) {
        visitFunction(F);
        InstVisitor::visit(F.begin(), F.end());

        InstrAllocas.clear();

        // Remove annotations afterwards to avoid iterator invalidation
        for (auto *I : Remove) {
            if (auto *II = dyn_cast<IntrinsicInst>(I))
                II->replaceAllUsesWith(II->getArgOperand(0));
            I->eraseFromParent();
        }
        Remove.clear();
    }

    void visit(BasicBlock &BB) {
        visitBasicBlock(BB);
        InstVisitor::visit(BB.begin(), BB.end());
    }

    void visit(Instruction &I) {
        visitInstruction(I);
        InstVisitor::visit(I);
    }

    void visitModule(Module &M) {
        DL = &M.getDataLayout();
        I64Ty = IRB.getInt64Ty();
        createHQFunctions(IRB, M, &OCF, &ODF, &OIF, &PCF, nullptr, &PDF, &PIF,
                          nullptr, &PMCF, nullptr, nullptr);
    }

    void visitFunction(Function &F) { currentAAResult = AACB(F); }

    void visitAnnotatedPointer(IntrinsicInst *I, bool Private) {
        Remove.push_back(I);

        auto *Base = const_cast<Value *>(simplify(I->getArgOperand(0), NO_GEP)),
             *Root = const_cast<Value *>(simplify(Base, RECURSE_GEP));

        // Skip constant data
        if (currentAAResult && currentAAResult->pointsToConstantMemory(Root))
            return;

        // Track lifetime of certain stack-allocated data
        if (auto *AI = dyn_cast<AllocaInst>(Root)) {
            // Compute type of the underlying data
            auto *BaseTy = getNonDecayedType(Base);
            if (BaseTy->isArrayTy() || BaseTy->isFloatingPointTy() ||
                BaseTy->isIntegerTy()) {
                // Primitive non-pointer types need invalidation when
                // out-of-scope
                InstrAllocas[AI].insert(Base);
            } else if (auto *STy = dyn_cast<StructType>(BaseTy)) {
                auto *SL = DL->getStructLayout(STy);
                // Sum types need to be zeroed if padding is present
                if (SL->hasPadding() && !InstrAllocas.count(AI)) {
                    IRB.SetInsertPoint(
                        getFirstNonAllocaInsertionPt(*AI->getParent()));
                    IRB.CreateMemSet(AI, IRB.getInt8(0), SL->getSizeInBytes(),
                                     AI->getAlign());
                    InstrAllocas.emplace(AI, SmallSet<Value *, 1>{});

                    outs() << AI->getFunction()->getName()
                           << ": Zeroing stack object of type '"
                           << *AI->getType()->getPointerElementType() << "'!\n";
                }
            }
        }

        DedupVector<Value *, 4> Stack;
        Stack.push_back(I);
        while (!Stack.empty()) {
            auto *V = Stack.pop_back_val();

            // Walk all uses of the value
            for (auto &U : V->uses()) {
                User *UU = U.getUser();

                if (auto *CB = dyn_cast<CallBase>(UU)) {
                    // If value is a function, skip examining the call itself
                    if (isa<Function>(V)) {
                        Stack.push_back(CB);
                        continue;
                    }

                    if (auto *II = dyn_cast<IntrinsicInst>(CB)) {
                        switch (II->getIntrinsicID()) {
                        case Intrinsic::lifetime_start:
                        case Intrinsic::lifetime_end:
                            // Use is a lifetime annotation, ignore it
                            continue;
                        case Intrinsic::memcpy:
                            // Skip already-instrumented calls
                            if (InstrMemCpys.count(II))
                                continue;
                            LLVM_FALLTHROUGH;
                        case Intrinsic::memset:
                        case Intrinsic::memmove:
                            // Use is an annotated memory function, instrument
                            // it
                            break;
                        case Intrinsic::launder_invariant_group:
                        case Intrinsic::strip_invariant_group:
                            // Use is an invariant annotation, recurse
                            assert(II->getArgOperand(0) == V &&
                                   "Invariant group must be on the argument!");
                            Stack.push_back(II);
                            continue;
                        default:
                            errs() << *II << "\n";
                            report_fatal_error("visitAnnotatedPointer(): "
                                               "Unsupported intrinsic!");
                        }
                    }

                    assert(CB->isArgOperand(&U) && "Use must be operand!");
                    unsigned ArgNo = U.getOperandNo();

                    // Lookup information about call behavior
                    ModRefInfo MRI = ModRefInfo::ModRef;
                    FunctionModRefBehavior FMRB =
                        FunctionModRefBehavior::FMRB_UnknownModRefBehavior;
                    if (currentAAResult) {
                        MRI = currentAAResult->getArgModRefInfo(CB, ArgNo);
                        FMRB = currentAAResult->getModRefBehavior(CB);
                    }

                    // Refine based on function name or C++ mangled name
                    const auto *F = dyn_cast_or_null<Function>(
                        CB->getCalledOperand()->stripPointerCasts());
                    const auto ParentName = CB->getFunction()->getName();
                    const bool isInDtorFunc = getDemangledName(ParentName) &&
                                              isDestructor(ParentName);
                    bool isCalledDtorFunc = false;
                    if (F) {
                        const auto Name = F->getName();
                        if (isHQFunction(Name))
                            continue;

                        const auto Demangled = getDemangledName(Name);
                        isCalledDtorFunc = Demangled && isDestructor(Name);
                        if (Demangled)
                            MRI = refineBehaviorDemangled(
                                MRI, *Demangled, ArgNo,
                                isConstructor(F->getName()), isCalledDtorFunc);
                    }

                    if (MRI == ModRefInfo::NoModRef ||
                        FMRB == FMRB_DoesNotAccessMemory ||
                        FMRB == FMRB_OnlyAccessesInaccessibleMem) {
                        // Use is not accessed, ignore it
                        continue;
                    }

                    // Fetch the object type, which may be a subtype
                    auto *VPtr = const_cast<Value *>(simplify(V, NO_GEP));
                    auto *VPtrTy = getNonDecayedType(VPtr);
                    const auto VPtrSz = DL->getTypeStoreSize(VPtrTy);
                    assert(VPtrSz && "Object size must be non-zero!");
                    // Use explicit load-extend for smaller types
                    const auto VPtrLoad = VPtrSz <= POINTER_VALUE_SIZE;

                    // Fetch the pointer and its underlying element type
                    if (isRefSet(MRI) || AAResults::onlyReadsMemory(FMRB)) {
                        // Use is a read, instrument it
                        IRB.SetInsertPoint(CB);
                        Value *Args[] = {
                            VPtr, VPtrLoad
                                      ? static_cast<Value *>(
                                            createSingleLoad(IRB, VPtr))
                                      : static_cast<Value *>(
                                            ConstantInt::get(I64Ty, VPtrSz))};
                        createCastedCall(IRB, VPtrLoad ? PCF : OCF, Args);
                        ++NumObjReads;
                    }

                    if (isModSet(MRI) || AAResults::doesNotReadMemory(FMRB)) {
                        // Use is a write, instrument it
                        auto CreateLambda = [&]() {
                            Value *Args[] = {VPtr, nullptr, nullptr};
                            const auto RemovableMemset =
                                isInDtorFunc && F &&
                                F->getIntrinsicID() == Intrinsic::memset &&
                                isa<Constant>(CB->getArgOperand(1)) &&
                                cast<Constant>(CB->getArgOperand(1))
                                    ->isZeroValue();
                            if (isCalledDtorFunc || RemovableMemset) {
                                if (!VPtrLoad) {
                                    Args[1] = ConstantInt::get(I64Ty, VPtrSz);
                                    createCastedCall(
                                        IRB, OIF,
                                        MutableArrayRef<Value *>(Args, 2));
                                    ++NumObjInvals;
                                } else {
                                    createCastedCall(
                                        IRB, PIF,
                                        MutableArrayRef<Value *>(Args, 2));
                                    ++NumInvals;
                                }

                                // Remove the initializer in std::hq_wrapper
                                // destructor
                                if (RemovableMemset) {
                                    dbgs()
                                        << ParentName << ": Removing call of '"
                                        << *CB << "'\n";
                                    Remove.push_back(CB);
                                }
                            } else {
                                Args[2] = IRB.getInt1(Private);
                                if (VPtrLoad) {
                                    Args[1] = createSingleLoad(IRB, VPtr);
                                    assert(Args[1] &&
                                           "Argument must be non-NULL!");
                                    createCastedCall(IRB, PDF, Args);
                                    ++NumStores;
                                } else {
                                    Args[1] = ConstantInt::get(I64Ty, VPtrSz);
                                    createCastedCall(IRB, ODF, Args);
                                    ++NumObjWrites;
                                }

                                if (CB->getIntrinsicID() == Intrinsic::memcpy)
                                    InstrMemCpys.insert(
                                        cast<IntrinsicInst>(CB));
                            }
                        };

                        // Insert into normal successor block for invokes
                        if (auto *II = dyn_cast<InvokeInst>(CB)) {
                            IRB.SetInsertPoint(
                                &*II->getNormalDest()->getFirstInsertionPt());
                            CreateLambda();
                        } else {
                            IRB.SetInsertPoint(CB->getNextNode());
                            CreateLambda();
                        }
                    }
                } else if (auto *BCO = dyn_cast<BitCastOperator>(UU)) {
                    assert(BCO->getOperand(0) == V &&
                           "Cast must be from the variable!");
                    // Use is a cast expression, recurse
                    Stack.push_back(BCO);
                } else if (auto *GEP = dyn_cast<GEPOperator>(UU)) {
                    assert(GEP->getPointerOperand() == V &&
                           "GEP must be on the variable!");
                    // Use is a child offset, recurse
                    Stack.push_back(GEP);
                } else if (auto *SI = dyn_cast<StoreInst>(UU)) {
                    // Use is a store, instrument it
                    Value *Dst = const_cast<Value *>(
                              simplify(SI->getPointerOperand())),
                          *Val = SI->getValueOperand();

                    Value *Args[] = {Dst, Val, nullptr};
                    IRB.SetInsertPoint(SI->getNextNode());

                    if (SI->isAtomic())
                        outs() << *SI << ": Store is atomic!\n";

                    auto Name = SI->getFunction()->getName();
                    auto Demangled = getDemangledName(Name);
                    if (Demangled && isDestructor(Name)) {
                        // Create an invalidate on the pointer
                        createCastedCall(IRB, PIF,
                                         MutableArrayRef<Value *>(Args, 2));
                        ++NumInvals;

                        // Remove the store in std::hq_wrapper destructor
                        if (const auto *CV = dyn_cast<Constant>(Val)) {
                            if (CV->isZeroValue()) {
                                dbgs() << Name << ": Removing store of '"
                                       << *Val << "'\n";
                                Remove.push_back(SI);
                            }
                        }
                    } else {
                        Args[2] = IRB.getInt1(Private);
                        // Create a define on the pointer
                        createCastedCall(IRB, PDF, Args);
                        ++NumStores;
                    }
                } else if (auto *LI = dyn_cast<LoadInst>(UU)) {
                    assert(LI->getPointerOperand() == V &&
                           "Load must be from the variable!");
                    // Use is a load, instrument it
                    Value *Src =
                        const_cast<Value *>(simplify(LI->getPointerOperand()));

                    if (LI->isAtomic())
                        outs() << *LI << ": Load is atomic!\n";

                    // Create a check on the pointer
                    Value *Args[] = {Src, LI};
                    IRB.SetInsertPoint(LI->getNextNode());
                    createCastedCall(IRB, PCF, Args);
                    ++NumLoads;
                } else if (auto *RI = dyn_cast<ReturnInst>(UU)) {
                    assert(RI->getReturnValue() == V &&
                           "Return must be of the variable!");
                    auto *F = RI->getFunction();

                    if (F->hasExternalLinkage())
                        outs() << F->getName()
                               << ": All uses may not be instrumented due to "
                                  "external linkage!\n";
                    // Use escapes into callers, recurse
                    Stack.push_back(F);
                } else if (auto *C = dyn_cast<Constant>(UU)) {
                    if (auto *F = dyn_cast<Function>(V->stripPointerCasts())) {
                        outs() << F->getName() << ": Ignoring use as data!\n";
                        continue;
                    }
                    errs() << *C << "\n";
                    report_fatal_error(
                        "visitAnnotatedPointer(): Unsupported constant!");
                } else if (auto *PN = dyn_cast<PHINode>(UU)) {
                    Stack.push_back(PN);
                } else if (auto *SI = dyn_cast<SelectInst>(UU)) {
                    Stack.push_back(SI);
                } else if (isa<ICmpInst>(UU)) {
                    continue;
                } else {
                    errs() << *V << "\n" << *UU << "\n";
                    report_fatal_error(
                        "visitAnnotatedPointer(): Unsupported value!");
                }
            }
        }
    }

    void visitLifetimeEnd(Value *V) {
        Value *Args[] = {V, nullptr};
        auto *Ty = V->getType()->getPointerElementType();

        // Create an invalidate on the pointer
        if (Ty->isArrayTy()) {
            Args[1] = ConstantInt::get(I64Ty, DL->getTypeStoreSize(Ty));
            assert(cast<ConstantInt>(Args[1]).getValue() != 0 &&
                   "Object size must be non-zero!");

            createCastedCall(IRB, OIF, Args);
        } else
            createCastedCall(IRB, PIF, Args);
        ++NumInvals;
    }

    void visitIntrinsicInst(IntrinsicInst &II) {
        const auto IID = II.getIntrinsicID();
        switch (IID) {
        default:
            break;
        case Intrinsic::lifetime_end: {
            auto It = InstrAllocas.find(
                cast<AllocaInst>(simplify(II.getArgOperand(1), RECURSE_GEP)));
            if (It != InstrAllocas.end()) {
                IRB.SetInsertPoint(&II);
                for (auto *I : It->second)
                    visitLifetimeEnd(I);
                InstrAllocas.erase(It);
            }
        } break;
        case Intrinsic::memcpy: {
            if (!LibraryFunctions)
                return;

            Value *A0 = const_cast<Value *>(
                      simplify(II.getArgOperand(0), NO_GEP)),
                  *A1 = const_cast<Value *>(
                      simplify(II.getArgOperand(1), NO_GEP)),
                  *A2 = II.getArgOperand(2);

            if (isCString(*A1) ||
                (!hasWrappedClassTy(*A0->getType()) &&
                 !hasWrappedClassTy(*A1->getType())) ||
                InstrMemCpys.count(&II))
                return;

            // Round up size to match alignment, if underlying value is smaller
            if (auto *CI = dyn_cast<ConstantInt>(A2)) {
                auto &V = CI->getValue();
                if (V.urem(POINTER_VALUE_SIZE))
                    A2 = ConstantInt::get(CI->getType(),
                                          (V + (POINTER_VALUE_SIZE - 1)) &
                                              ~(POINTER_VALUE_SIZE - 1));
            }

            // Different number of arguments, recreate the call
            IRB.SetInsertPoint(II.getNextNode());
            Value *Args[] = {A0, A1, A2};
            createCastedCall(IRB, PMCF, Args);
            InstrMemCpys.insert(&II);
            ++NumCopy;
        } break;
        case Intrinsic::ptr_annotation: {
            const auto Type = isHQAnnotatedPointer(&II);
            if (Type != NO_DFI)
                visitAnnotatedPointer(&II, Type == DFI_Private);
        } break;
        case Intrinsic::var_annotation:
            errs() << II << "\n";
            report_fatal_error(
                "visitIntrinsicInst(): Unsupported variable annotation!");
            break;
        }
    }

    void visitReturnInst(ReturnInst &RI) {
        // Invalidate for roots with missing lifetime end intrinsic (e.g. O0)
        // A functions may have multiple exits, so do not clear the list
        for (const auto &P : InstrAllocas) {
            IRB.SetInsertPoint(&RI);
            for (auto *I : P.second)
                visitLifetimeEnd(I);
        }
    }
};

/* Create DFI instrumentation */
static bool createDFIInstrumentation(Module &M, AliasAnalysisCallback AACB) {
    if (!RunDFI)
        return false;

    LLVMContext &C = M.getContext();
    InstrumentVisitor IV(C, AACB);
    IV.visit(M);

    bool Changed = NumLoads || NumStores || NumInvals || NumObjReads ||
                   NumObjWrites || NumObjInvals || NumCopy;
    if (Changed) {
        outs() << M.getName() << ": Instrumented ";
        if (NumLoads || NumStores || NumInvals || NumObjReads || NumObjWrites ||
            NumObjInvals)
            outs() << "values (" << NumLoads << " loads, " << NumStores
                   << " stores, " << NumInvals << " invalidates), objects ("
                   << NumObjReads << " reads, " << NumObjWrites << " writes, "
                   << NumObjInvals << " invalidates); ";
        if (NumCopy)
            outs() << "calls (" << NumCopy << " copies); ";
        outs() << "\n";
    }

    Changed |= performInlining(M, InlinePath);
    return Changed;
}

/* Implementation for legacy pass manager */
void DFIInstrumentLegacyPass::getAnalysisUsage(AnalysisUsage &AU) const {
    if (UseAliasAnalysis)
        AU.addRequired<AAResultsWrapperPass>();
    AU.setPreservesCFG();
}

bool DFIInstrumentLegacyPass::runOnModule(Module &M) {
    auto AACallback = [this](Function &F) -> AAResults * {
        return UseAliasAnalysis && !F.isDeclaration()
                   ? &this->getAnalysis<AAResultsWrapperPass>(F).getAAResults()
                   : nullptr;
    };
    return createDFIInstrumentation(M, AACallback);
}

char DFIInstrumentLegacyPass::ID = 0;

// Use this because RegisterPass<...>(...) does not support dependent passes
INITIALIZE_PASS_BEGIN(DFIInstrumentLegacyPass, DEBUG_TYPE,
                      "DFI Instrumentation Pass", false, false)
INITIALIZE_PASS_DEPENDENCY(AAResultsWrapperPass)
INITIALIZE_PASS_END(DFIInstrumentLegacyPass, DEBUG_TYPE,
                    "DFI Instrumentation Pass", false, false)

static void RegisterLegacyPasses(const PassManagerBuilder &Builder,
                                 legacy::PassManagerBase &PM) {
    bool Inline = !InlinePath.empty() || getInlinePath();
    PassRegistry *PR = PassRegistry::getPassRegistry();

    PM.add(createPromoteMemoryToRegisterPass());
    initializeDFIInstrumentLegacyPassPass(*PR);
    PM.add(new DFIInstrumentLegacyPass());
#ifndef NDEBUG
    PM.add(createVerifierPass());
#endif /* NDEBUG */
    if (Inline) {
        PM.add(createAlwaysInlinerLegacyPass());
        PM.add(createGlobalDCEPass());
    }
}

static RegisterStandardPasses DFIInstrumentRegister(
    PassManagerBuilder::EP_ModuleOptimizerEarly,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
        RegisterLegacyPasses(Builder, PM);
    });

static RegisterStandardPasses DFIInstrumentRegisterL0(
    PassManagerBuilder::EP_EnabledOnOptLevel0,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
        RegisterLegacyPasses(Builder, PM);
    });

/* Implementation for new pass manager */
void DFIInstrumentPass::create(ModulePassManager &MPM) {
    bool Inline = !InlinePath.empty() || getInlinePath();

    if (UseAliasAnalysis)
        MPM.addPass(RequireAnalysisPass<AAManager, Module>());

    FunctionPassManager FPM;
    FPM.addPass(PromotePass());
    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
    MPM.addPass(DFIInstrumentPass());
#ifndef NDEBUG
    MPM.addPass(VerifierPass());
#endif /* NDEBUG */
    if (Inline) {
        MPM.addPass(AlwaysInlinerPass());
        MPM.addPass(GlobalDCEPass());
    }
}

PreservedAnalyses DFIInstrumentPass::run(Module &M,
                                         ModuleAnalysisManager &MAM) {
    PassBuilder PB;
    PB.registerModuleAnalyses(MAM);
    auto &FAM =
        MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
    auto AACallback = [&FAM](Function &F) -> AAResults * {
        return UseAliasAnalysis ? &FAM.getResult<AAManager>(F) : nullptr;
    };
    createDFIInstrumentation(M, AACallback);
    return PreservedAnalyses::all();
}

#undef DEBUG_TYPE
