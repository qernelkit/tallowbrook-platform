// Object-store upload requests. The store requires a Content-MD5 header on every PUT (its own
// integrity check, not a security control), computed over the container bytes.
#include "store/object_upload.hh"

#include <botan/base64.h>
#include <botan/hash.h>

namespace vaultarc {

UploadRequest build_upload(std::string_view bucket, std::string_view object, std::span<const uint8_t> body) {
    auto md5 = Botan::HashFunction::create_or_throw("MD5");
    md5->update(body.data(), body.size());
    auto digest = md5->final();

    UploadRequest req;
    req.path = "/" + std::string(bucket) + "/" + std::string(object);
    req.content_md5 = Botan::base64_encode(digest);
    req.content_length = body.size();
    return req;
}

}  // namespace vaultarc
