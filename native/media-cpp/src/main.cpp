// vaultarc entry point.
#include <string>
#include <vector>

#include "cli/commands.hh"

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    return vaultarc::run_command(args);
}
