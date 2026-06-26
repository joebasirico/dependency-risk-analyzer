require 'digest'
require 'fileutils'
require 'json'

module DependencyRisk
  class Cache
    def initialize(dir:, force: false)
      @dir = dir
      @force = force
    end

    def fetch_json(namespace, key)
      return nil if @force

      file = path(namespace, key)
      return nil unless File.exist?(file)

      JSON.parse(File.read(file))
    rescue JSON::ParserError
      nil
    end

    def write_json(namespace, key, value)
      file = path(namespace, key)
      FileUtils.mkdir_p(File.dirname(file))
      File.write(file, JSON.pretty_generate(value))
      value
    end

    def fetch_or_store(namespace, key)
      cached = fetch_json(namespace, key)
      return cached if cached

      fresh = yield
      write_json(namespace, key, fresh) if fresh
      fresh
    end

    private

    def path(namespace, key)
      digest = Digest::SHA256.hexdigest(key.to_s)
      File.join(@dir, namespace.to_s, "#{digest}.json")
    end
  end
end
