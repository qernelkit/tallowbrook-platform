# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../app/services/upload_fingerprint"

class UploadFingerprintTest < Minitest::Test
  def test_storage_path_fans_out
    path = UploadFingerprint.storage_path("ab12cd34ef", "Scan 0001.PDF")

    assert_equal "uploads/ab/12/ab12cd34ef.pdf", path
  end

  def test_storage_path_without_extension
    assert_equal "uploads/00/11/0011.bin", UploadFingerprint.storage_path("0011", "noext")
  end
end
