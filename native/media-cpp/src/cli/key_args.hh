#ifndef VAULTARC_KEY_ARGS_HH
#define VAULTARC_KEY_ARGS_HH

#include <string_view>

namespace vaultarc {

enum class KeyArgKind { kMissing, kPath, kInlinePem };

KeyArgKind classify_key_arg(std::string_view arg);

}  // namespace vaultarc

#endif
