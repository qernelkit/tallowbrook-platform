#ifndef VAULTARC_DE_EXCHANGE_HH
#define VAULTARC_DE_EXCHANGE_HH

#include <span>

#include "vaultarc.hh"

namespace vaultarc {

struct PartnerExchange {
    Bytes our_public;
    Bytes shared_secret;
};

const char* partner_key_path();
PartnerExchange exchange_with_partner(std::span<const uint8_t> partner_public, std::span<const uint8_t> info);

}  // namespace vaultarc

#endif
