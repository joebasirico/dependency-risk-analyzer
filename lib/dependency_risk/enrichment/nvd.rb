require 'uri'

module DependencyRisk
  module Enrichment
    class Nvd
      BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'.freeze
      HOST = 'services.nvd.nist.gov'.freeze

      def initialize(cache:)
        @cache = cache
        @http = HttpJsonClient.new(allowed_host: HOST)
        @api_key = Credentials.fetch('NVD_API_KEY', 'op://Private/NVDAPIKey/credential')
      end

      def enrich!(package)
        vulnerabilities = if package.cpes.any?
                            package.cpes.flat_map { |cpe| query_by_cpe(cpe) }
                          else
                            query_by_keyword(package.name)
                          end

        vulnerabilities.each do |vulnerability|
          vulnerability.package_name = package.name
          vulnerability.package_type = package.type
          vulnerability.package_version = package.version
          package.add_vulnerability(vulnerability)
        end
      end

      private

      def query_by_cpe(cpe)
        query("#{BASE_URL}?cpeName=#{URI.encode_www_form_component(cpe)}", "cpe:#{cpe}")
      end

      def query_by_keyword(keyword)
        return [] if keyword.to_s.empty?

        query("#{BASE_URL}?keywordSearch=#{URI.encode_www_form_component(keyword)}", "keyword:#{keyword}")
      end

      def query(url, cache_key)
        body = @cache.fetch_or_store('nvd', cache_key) do
          headers = @api_key ? { 'apiKey' => @api_key } : {}
          @http.get_json(url, headers)
        end

        Array(body && body['vulnerabilities']).map { |item| Models::Vulnerability.from_nvd_cve(item) }
      rescue StandardError
        []
      end
    end
  end
end
