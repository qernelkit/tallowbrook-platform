# frozen_string_literal: true

require "erb"

# The sign-off block appended to emails staff send from the admin.
module EmailSignature
  module_function

  def signature_html(staff)
    name = ERB::Util.html_escape(staff.display_name)
    role = ERB::Util.html_escape(staff.role.to_s.capitalize)
    <<~HTML
      <p style="margin-top:16px">Kind regards,<br>
      <strong>#{name}</strong><br>
      #{role}, Tallowbrook</p>
      <p style="color:#888;font-size:12px">Tallowbrook Logistics · tallowbrook.example</p>
    HTML
  end

  def signature_text(staff)
    "Kind regards,\n#{staff.display_name}\n#{staff.role.to_s.capitalize}, Tallowbrook"
  end
end
