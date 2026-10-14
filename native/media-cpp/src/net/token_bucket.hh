#ifndef VAULTARC_TOKEN_BUCKET_HH
#define VAULTARC_TOKEN_BUCKET_HH

namespace vaultarc {

class TokenBucket {
public:
    TokenBucket(double rate_per_s, double burst);
    bool try_take(double now_s, double cost);

private:
    void refill(double now_s);
    double rate_;
    double burst_;
    double tokens_;
    double last_s_ = 0.0;
};

}  // namespace vaultarc

#endif
