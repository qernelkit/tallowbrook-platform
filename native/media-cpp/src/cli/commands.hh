#ifndef VAULTARC_COMMANDS_HH
#define VAULTARC_COMMANDS_HH

#include <span>
#include <string>
#include <vector>

namespace vaultarc {

int run_command(const std::vector<std::string>& args);
int run_self_check();

}  // namespace vaultarc

#endif
