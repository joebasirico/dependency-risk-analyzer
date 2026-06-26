require 'date'
require 'uri'

module DependencyRisk
  module Enrichment
    class LibrariesIo
      BASE_URL = 'https://libraries.io/api'.freeze
      HOST = 'libraries.io'.freeze
      TYPE_MAP = {
        'npm' => 'NPM',
        'gem' => 'Rubygems',
        'bundle' => 'Rubygems',
        'ruby' => 'Rubygems',
        'java-archive' => 'Maven',
        'python' => 'pypi',
        'pypi' => 'pypi'
      }.freeze
      REVERSE_TYPE_MAP = {
        'NPM' => 'npm',
        'Rubygems' => 'gem',
        'Maven' => 'java-archive',
        'pypi' => 'python',
        'PyPI' => 'python'
      }.freeze

      def initialize(cache:, api_key: nil)
        @cache = cache
        @api_key = api_key || Credentials.fetch(
          'LIBRARIES_IO_API_KEY',
          [
            'op://Personal/Libraries.ioAPIToken/credential',
            'op://Private/Libraries.ioAPIToken/credential',
            'op://Employee/Libraries.ioAPIToken/credential'
          ]
        )
        @http = HttpJsonClient.new(allowed_host: HOST)
      end

      def available?
        !@api_key.to_s.empty?
      end

      def enrich!(package)
        return false unless available?

        info = project(package)
        return false unless info

        package.description = info['description']
        package.repository_url = info['repository_url']
        package.licenses = normalize_licenses(info['licenses']) unless info['licenses'].nil?
        package.sourcerank = info['rank']
        package.homepage = info['homepage']
        package.latest_version = info['latest_stable_release_number']
        package.latest_release_published_at = parse_time(info['latest_stable_release_published_at'])
        current = Array(info['versions']).find { |version| version['number'].to_s == package.version.to_s }
        package.current_release_published_at = parse_time(current['published_at']) if current
        true
      end

      def project(package)
        platform = platform_for(package.type)
        return nil unless platform

        key = "project:#{platform}:#{package.name}"
        @cache.fetch_or_store('libraries_io', key) do
          @http.get_json("#{BASE_URL}/#{platform}/#{encoded_name(package)}?api_key=#{@api_key}")
        end
      rescue StandardError
        nil
      end

      def dependencies(package)
        platform = platform_for(package.type)
        return [] unless available? && platform && package.version

        key = "deps:#{platform}:#{package.name}:#{package.version}"
        response = @cache.fetch_or_store('libraries_io', key) do
          @http.get_json("#{BASE_URL}/#{platform}/#{encoded_name(package)}/#{URI.encode_www_form_component(package.version.to_s)}/dependencies?api_key=#{@api_key}")
        end

        Array(response && response['dependencies']).each_with_object([]) do |dep, items|
          next if dep['kind'] == 'Development'

          type = REVERSE_TYPE_MAP[dep['platform']] || package.type
          items << Models::Package.new(name: dep['project_name'], type: type)
        end
      rescue StandardError
        []
      end

      private

      def platform_for(type)
        TYPE_MAP[type]
      end

      def encoded_name(package)
        URI.encode_www_form_component(libraries_io_name(package))
      end

      def libraries_io_name(package)
        if package.type == 'java-archive' && package.metadata.dig('pomProperties', 'groupId')
          "#{package.metadata.dig('pomProperties', 'groupId')}:#{package.metadata.dig('pomProperties', 'artifactId')}"
        else
          package.name
        end
      end

      def normalize_licenses(raw)
        Array(raw).flat_map { |license| license.to_s.split(',') }.map(&:strip).reject(&:empty?).uniq
      end

      def parse_time(value)
        value && DateTime.parse(value)
      rescue ArgumentError
        nil
      end
    end
  end
end
