// Upload rate limiter: a classic token bucket smoothing bursts so the gateway uplink is not starved
// while a big archive uploads. "Token" here is a rate-limiter token, not a credential.
#include "net/token_bucket.hh"

#include <algorithm>

namespace vaultarc {

TokenBucket::TokenBucket(double rate_per_s, double burst) : rate_(rate_per_s), burst_(burst), tokens_(burst) {}

bool TokenBucket::try_take(double now_s, double cost) {
    refill(now_s);
    if (tokens_ < cost)
        return false;
    tokens_ -= cost;
    return true;
}

void TokenBucket::refill(double now_s) {
    if (last_s_ > 0.0) {
        tokens_ = std::min(burst_, tokens_ + (now_s - last_s_) * rate_);
    }
    last_s_ = now_s;
}

}  // namespace vaultarc
