#ifndef VAULTARC_OBJECT_UPLOAD_HH
#define VAULTARC_OBJECT_UPLOAD_HH

#include <span>
#include <string>
#include <string_view>

#include "vaultarc.hh"

namespace vaultarc {

struct UploadRequest {
    std::string path;
    std::string content_md5;
    size_t content_length = 0;
};

UploadRequest build_upload(std::string_view bucket, std::string_view object, std::span<const uint8_t> body);

}  // namespace vaultarc

#endif
