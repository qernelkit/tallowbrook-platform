// `--key` argument handling: the argument can be a path to a PEM key file or, in scripts, the key
// material inline. This only classifies the argument; loading is done by the crypto modules.
#include "cli/key_args.hh"

namespace vaultarc {
namespace {
constexpr std::string_view kPemKeyPrefix = "-----BEGIN PRIVATE KEY-----";
}  // namespace

KeyArgKind classify_key_arg(std::string_view arg) {
    if (arg.empty())
        return KeyArgKind::kMissing;
    if (arg.substr(0, kPemKeyPrefix.size()) == kPemKeyPrefix)
        return KeyArgKind::kInlinePem;
    return KeyArgKind::kPath;
}

}  // namespace vaultarc
