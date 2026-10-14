#include "cli/commands.hh"
#include "cli/key_args.hh"
#include "test.hh"

using namespace vaultarc;

TEST(key_arg_classification) {
    CHECK(classify_key_arg("") == KeyArgKind::kMissing);
    CHECK(classify_key_arg("/etc/tallowbrook/manifest.key") == KeyArgKind::kPath);
    CHECK(classify_key_arg("-----BEGIN PRIVATE KEY-----\nMII...") == KeyArgKind::kInlinePem);
}

TEST(help_is_handled) {
    CHECK(run_command({"--help"}) == 0);
    CHECK(run_command({}) == 2);
}
