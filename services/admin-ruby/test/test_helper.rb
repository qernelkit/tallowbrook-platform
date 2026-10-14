# frozen_string_literal: true

ENV["RAILS_ENV"] ||= "test"

require "minitest/autorun"
require "active_support"
require "active_support/core_ext"

# Service and lib tests run without booting Rails or touching the database.
StaffStub = Struct.new(:display_name, :role, :email, keyword_init: true)
