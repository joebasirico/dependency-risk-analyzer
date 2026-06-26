require 'json'
require 'net/http'
require 'uri'

module DependencyRisk
  class HttpJsonClient
    def initialize(allowed_host:, timeout: 15)
      @allowed_host = allowed_host
      @timeout = timeout
    end

    def get_json(url, headers = {})
      uri = URI(url)
      validate_uri!(uri)

      request = Net::HTTP::Get.new(uri)
      headers.each { |key, value| request[key] = value if value && !value.to_s.empty? }

      response = Net::HTTP.start(uri.host, uri.port, use_ssl: true,
                                 open_timeout: @timeout, read_timeout: @timeout) do |http|
        http.request(request)
      end

      unless response.is_a?(Net::HTTPSuccess)
        raise "HTTP request to #{uri.host} failed with #{response.code}"
      end

      JSON.parse(response.body)
    end

    private

    def validate_uri!(uri)
      raise 'Only HTTPS API requests are supported' unless uri.scheme == 'https'
      raise "Unexpected API host #{uri.host}" unless uri.host == @allowed_host
    end
  end
end
