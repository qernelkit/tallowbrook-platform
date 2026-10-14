# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../app/lib/email_signature"

class EmailSignatureTest < Minitest::Test
  def setup
    @staff = StaffStub.new(display_name: "Ana <Ops> Ruiz", role: "operations", email: "ana@tallowbrook.example")
  end

  def test_html_is_escaped
    html = EmailSignature.signature_html(@staff)

    assert_includes html, "Ana &lt;Ops&gt; Ruiz"
    assert_includes html, "Operations, Tallowbrook"
  end

  def test_text_version
    assert_equal "Kind regards,\nAna <Ops> Ruiz\nOperations, Tallowbrook", EmailSignature.signature_text(@staff)
  end
end
