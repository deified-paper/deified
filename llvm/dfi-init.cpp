#include "llvm/PassRegistry.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include "dfi-init.h"
#include "dfi-instrument.h"
#include "hq-syscall.h"
#include "utils.h"

using namespace llvm;

static constexpr char TEST_PLUGIN_NAME[] = "DFI Passes";
static constexpr char TEST_PLUGIN_VERSION[] = "1.0";

cl::opt<bool> RunDFI("run-dfi",
                     cl::desc("Enable DFI instrumentation (default = true)"),
                     cl::init(true));

// FIXME: Checks an environment variable, because LTO driver will not pass LLVM
// command-line arguments, and LTO plugin will not parse them
cl::opt<std::string> InlinePath(
    "hq-inline-path",
    cl::desc("Path to bitcode implementation of the interface's messaging "
             "functions, which will be inlined after optimization, if "
             "provided. (default = <empty>, or HQ_INLINE_PATH)"),
    cl::value_desc("path"));

// Use static object to initialize passes when the plugin is loaded, so that
// they are available in 'opt'. Based on Polly.cpp/RegisterPasses.cpp.
class StaticInitializer {
    static void initializeDFIPasses(PassRegistry &PR) {
        initializeDFIInstrumentLegacyPassPass(PR);
        initializeHQSyscallLegacyPassPass(PR);
    }

  public:
    StaticInitializer() {
        PassRegistry &PR = *PassRegistry::getPassRegistry();
        initializeDFIPasses(PR);

        // FIXME: Checks an environment variable, because Clang `cc1as` driver
        // does not load LLVM passes, which will break compilation on assembly
        // files due to unrecognized `-mllvm -hq-syscalls-only=true` argument
        if (getSysCallsOnly()) {
            outs() << "Only instrumenting system calls, disabling all other "
                      "instrumentation!\n";
            RunDFI = false;
            RunSysCalls = true;
        }
    }
};

static StaticInitializer Initializer;

extern "C" PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, TEST_PLUGIN_NAME, TEST_PLUGIN_VERSION,
            [](PassBuilder &PB) {
                PB.registerPipelineParsingCallback(
                    [](StringRef Name, ModulePassManager &MPM,
                       ArrayRef<PassBuilder::PipelineElement> InnerPipeline) {
                        if (Name.equals("dfi-instrument")) {
                            DFIInstrumentPass::create(MPM);
                            return true;
                        } else if (Name.equals("hq-syscall")) {
                            HQSyscallPass::create(MPM);
                            return true;
                        }

                        return false;
                    });

                PB.registerPipelineStartEPCallback(
                    [](ModulePassManager &MPM) { HQSyscallPass::create(MPM); });

                // FIXME: Needs to be ModulePass
                // PB.registerPeepholeEPCallback(
                //     [](FunctionPassManager &FPM,
                //        PassBuilder::OptimizationLevel Level) {
                //         DFIInstrumentPass::create(FPM);
                //     });
            }};
}
