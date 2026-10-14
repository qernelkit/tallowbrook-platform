#ifndef VAULTARC_UPLOAD_CLIENT_HH
#define VAULTARC_UPLOAD_CLIENT_HH

#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace Botan::TLS {
class Client;
}

namespace vaultarc {

class UploadSink {
public:
    virtual ~UploadSink() = default;
    virtual void on_wire(std::span<const uint8_t> data) = 0;
    virtual void on_plaintext(std::span<const uint8_t> data) = 0;
    virtual void on_alert(const std::string& alert) = 0;
};

class UploadClient {
public:
    explicit UploadClient(UploadSink& sink);
    ~UploadClient();
    void connect(std::string_view host);
    void feed(std::span<const uint8_t> wire);

private:
    UploadSink& sink_;
    std::unique_ptr<Botan::TLS::Client> client_;
};

}  // namespace vaultarc

#endif
