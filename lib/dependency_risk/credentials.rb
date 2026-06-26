require 'open3'

module DependencyRisk
  module Credentials
    module_function

    def fetch(env_key, op_paths = nil)
      value = ENV[env_key].to_s.strip
      return value unless value.empty?

      paths = credential_paths(env_key, op_paths)
      return nil if paths.empty? || !executable?('op')

      paths.each do |op_path|
        stdout, _stderr, status = Open3.capture3('op', 'read', op_path)
        secret = stdout.to_s.strip
        return secret if status.success? && !secret.empty?
      end

      nil
    rescue Errno::ENOENT
      nil
    end

    def credential_paths(env_key, op_paths)
      [
        ENV["#{env_key}_OP_PATH"],
        ENV["#{env_key}_OP_REF"],
        *Array(op_paths)
      ].compact.map(&:to_s).map(&:strip).reject(&:empty?).uniq
    end

    def github_token
      value = ENV['GITHUB_TOKEN'].to_s.strip
      return value unless value.empty?
      return nil unless executable?('gh')

      stdout, _stderr, status = Open3.capture3('gh', 'auth', 'token')
      token = stdout.to_s.strip
      status.success? && !token.empty? ? token : nil
    rescue Errno::ENOENT
      nil
    end

    def executable?(command)
      _stdout, _stderr, status = Open3.capture3('which', command)
      status.success?
    end
  end
end
