#include "llvm/PassRegistry.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include "hq-syscall.h"
#include "utils.h"

using namespace llvm;

static constexpr char TEST_PLUGIN_NAME[] = "HQ System Call Pass";
static constexpr char TEST_PLUGIN_VERSION[] = "1.0";

// Use static object to initialize passes when the plugin is loaded, so that
// they are available in 'opt'. Based on Polly.cpp/RegisterPasses.cpp.
class StaticInitializer {
    static void initializeHQPasses(PassRegistry &PR) {
        initializeHQSyscallLegacyPassPass(PR);
    }

  public:
    StaticInitializer() {
        PassRegistry &PR = *PassRegistry::getPassRegistry();
        initializeHQPasses(PR);
    }
};

static StaticInitializer Initializer;

extern "C" PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, TEST_PLUGIN_NAME, TEST_PLUGIN_VERSION,
            [](PassBuilder &PB) {
                PB.registerPipelineParsingCallback(
                    [](StringRef Name, ModulePassManager &MPM,
                       ArrayRef<PassBuilder::PipelineElement> InnerPipeline) {
                        if (Name.equals("hq-syscall")) {
                            HQSyscallPass::create(MPM);
                            return true;
                        }

                        return false;
                    });

                PB.registerPipelineStartEPCallback(
                    [](ModulePassManager &MPM) { HQSyscallPass::create(MPM); });
            }};
}
