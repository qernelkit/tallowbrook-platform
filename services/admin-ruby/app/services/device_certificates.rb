# frozen_string_literal: true

# Client certificates for depot scanners. A scanner creates its own key and sends a CSR at
# enrolment; operations rotate the depot scanner CA once a year.
class DeviceCertificates
  CA_VALIDITY = 5 * 365 * 24 * 60 * 60
  DEVICE_VALIDITY = 397 * 24 * 60 * 60

  def initialize(vault)
    @vault = vault
  end

  # Creates a new depot scanner CA and hands its key and certificate to the vault.
  def rotate_ca!
    ca_key = OpenSSL::PKey::EC.generate("secp384r1")
    name = OpenSSL::X509::Name.parse("/O=Tallowbrook/OU=Depot Devices/CN=Tallowbrook Depot Scanner CA #{Date.current.year}")
    cert = build(subject: name, subject_key: ca_key, issuer: nil, validity: CA_VALIDITY)
    sign!(cert, ca_key)
    @vault.store(ca_key.private_to_pem, cert.to_pem)
    cert
  end

  def issue(device, csr_pem)
    csr = OpenSSL::X509::Request.new(csr_pem)
    raise ArgumentError, "CSR for #{device.serial} is not self-consistent" unless csr.verify(csr.public_key)

    ca_key = OpenSSL::PKey.read(@vault.key_pem)
    ca_cert = OpenSSL::X509::Certificate.new(@vault.cert_pem)
    name = OpenSSL::X509::Name.new([["O", "Tallowbrook"], ["OU", "Depot #{device.depot_code}"], ["CN", device.serial]])
    cert = build(subject: name, subject_key: csr.public_key, issuer: ca_cert, validity: DEVICE_VALIDITY)
    sign!(cert, ca_key)
    device.update!(cert_serial: cert.serial.to_s(16), cert_expires_at: cert.not_after)
    cert.to_pem
  end

  private

  def build(subject:, subject_key:, issuer:, validity:)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = OpenSSL::BN.new(SecureRandom.hex(16), 16)
    cert.subject = subject
    cert.issuer = issuer ? issuer.subject : subject
    cert.public_key = subject_key
    cert.not_before = Time.now.utc
    cert.not_after = cert.not_before + validity

    ext = OpenSSL::X509::ExtensionFactory.new
    ext.subject_certificate = cert
    ext.issuer_certificate = issuer || cert
    if issuer
      cert.add_extension(ext.create_extension("basicConstraints", "CA:FALSE", true))
      cert.add_extension(ext.create_extension("keyUsage", "digitalSignature", true))
      cert.add_extension(ext.create_extension("extendedKeyUsage", "clientAuth"))
    else
      cert.add_extension(ext.create_extension("basicConstraints", "CA:TRUE,pathlen:0", true))
      cert.add_extension(ext.create_extension("keyUsage", "keyCertSign,cRLSign", true))
    end
    cert
  end

  def sign!(cert, ca_key)
    cert.sign(ca_key, OpenSSL::Digest.new("SHA384"))
  end
end
