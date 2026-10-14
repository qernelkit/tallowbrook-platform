// Botan TLS client to the archive object store, using ArchiveUploadPolicy. The container is streamed
// up with a PUT; the store does its own object integrity with the Content-MD5 header.
#include "net/upload_client.hh"

#include <botan/auto_rng.h>
#include <botan/certstor_system.h>
#include <botan/tls_client.h>
#include <botan/tls_session_manager_noop.h>

#include "net/upload_policy.hh"

namespace vaultarc {
namespace {

class StoreCallbacks : public Botan::TLS::Callbacks {
public:
    explicit StoreCallbacks(UploadSink& sink) : sink_(sink) {}

    void tls_emit_data(std::span<const uint8_t> data) override { sink_.on_wire(data); }
    void tls_record_received(uint64_t, std::span<const uint8_t> data) override { sink_.on_plaintext(data); }
    void tls_alert(Botan::TLS::Alert alert) override { sink_.on_alert(alert.type_string()); }

private:
    UploadSink& sink_;
};

}  // namespace

UploadClient::UploadClient(UploadSink& sink) : sink_(sink) {}

void UploadClient::connect(std::string_view host) {
    Botan::TLS::Server_Information info(std::string(host), 443);
    auto callbacks = std::make_shared<StoreCallbacks>(sink_);
    auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_Noop>();
    auto creds = std::make_shared<Botan::Credentials_Manager>();
    auto policy = std::make_shared<ArchiveUploadPolicy>();
    auto rng = std::make_shared<Botan::AutoSeeded_RNG>();

    client_ = std::make_unique<Botan::TLS::Client>(callbacks, session_mgr, creds, policy, rng, info);
}

void UploadClient::feed(std::span<const uint8_t> wire) {
    if (client_)
        client_->received_data(wire.data(), wire.size());
}

UploadClient::~UploadClient() = default;

}  // namespace vaultarc
