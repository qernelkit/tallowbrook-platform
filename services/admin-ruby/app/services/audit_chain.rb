# frozen_string_literal: true

# Staff actions are appended to a hash-chained audit log: each entry's hash covers the entry and
# the previous hash, so a deleted or edited entry breaks the chain from that point on.
class AuditChain
  GENESIS = "0" * 64

  def initialize(entries = [])
    @entries = entries
  end

  def append(actor:, action:, target:, at: Time.now.utc)
    entry = { "actor" => actor, "action" => action, "target" => target, "at" => at.iso8601, "prev" => head }
    entry["hash"] = link(entry)
    @entries << entry
    entry
  end

  def head
    @entries.last&.fetch("hash") || GENESIS
  end

  def intact?
    prev = GENESIS
    @entries.all? do |entry|
      ok = entry["prev"] == prev && entry["hash"] == link(entry)
      prev = entry["hash"]
      ok
    end
  end

  private

  def link(entry)
    digest = OpenSSL::Digest.new("SHA3-256")
    digest << entry["prev"]
    digest << JSON.generate(entry.slice("actor", "action", "target", "at"))
    digest.hexdigest
  end
end
