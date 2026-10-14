# frozen_string_literal: true

require "shellwords"

# Drops daily manifests into the carrier's inbound directory over SSH.
class CarrierSftp
  class UploadFailed < StandardError; end

  def drop(carrier, filename, body)
    Net::SSH.start(carrier.sftp_host, carrier.sftp_user,
                   keys: [Rails.root.join("storage/keys/carrier_drop").to_s],
                   kex: %w[ecdh-sha2-nistp384 ecdh-sha2-nistp256 diffie-hellman-group14-sha256],
                   encryption: %w[aes256-gcm@openssh.com aes256-ctr],
                   verify_host_key: :always,
                   non_interactive: true,
                   timeout: 20) do |session|
      upload(session, "inbound/#{filename}", body)
    end
  end

  private

  def upload(session, path, body)
    session.open_channel do |channel|
      channel.exec("cat > #{Shellwords.escape(path)}") do |ch, success|
        raise UploadFailed, "carrier refused #{path}" unless success

        ch.send_data(body)
        ch.eof!
      end
    end
    session.loop
  end
end
