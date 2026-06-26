require 'open3'

module DependencyRisk
  module Credentials
    module_function

    def fetch(env_key, op_path = nil)
      value = ENV[env_key].to_s.strip
      return value unless value.empty?

      return nil unless op_path && executable?('op')

      stdout, status = Open3.capture2('op', 'read', op_path)
      status.success? ? stdout.strip : nil
    rescue Errno::ENOENT
      nil
    end

    def executable?(command)
      _stdout, status = Open3.capture2('which', command)
      status.success?
    end
  end
end
