require 'date'
require 'json'
require 'net/http'
require 'uri'

module DependencyRisk
  module Enrichment
    class Github
      BASE_URL = 'https://api.github.com'.freeze
      HOST = 'api.github.com'.freeze

      def initialize(cache:)
        @cache = cache
        @http = HttpJsonClient.new(allowed_host: HOST)
        @token = Credentials.fetch('GITHUB_TOKEN')
      end

      def enrich!(package)
        owner, repo = owner_repo(package.repository_url)
        return false unless owner && repo

        package.github = {
          'issues' => open_issue_count(owner, repo),
          'prs' => open_pr_count(owner, repo),
          'last_commit' => last_commit_date(owner, repo)
        }
        true
      rescue StandardError
        false
      end

      def owner_repo(repository_url)
        return [nil, nil] unless repository_url

        match = repository_url.match(%r{github\.com[:/]([\w.\-]+)/([\w.\-]+?)(?:\.git)?(?:/|\z)})
        return [nil, nil] unless match

        [match[1], match[2]]
      end

      private

      def open_issue_count(owner, repo)
        issues = paginated_get("#{BASE_URL}/repos/#{owner}/#{repo}/issues?state=open&per_page=100")
        issues.count { |item| item['pull_request'].nil? }
      end

      def open_pr_count(owner, repo)
        paginated_get("#{BASE_URL}/repos/#{owner}/#{repo}/pulls?state=open&per_page=100").count
      end

      def last_commit_date(owner, repo)
        commits = get_json("#{BASE_URL}/repos/#{owner}/#{repo}/commits?per_page=1")
        first = Array(commits).first
        first && first.dig('commit', 'author', 'date')
      end

      def paginated_get(url)
        results = []
        next_url = url

        while next_url
          body, link_header = get_json_with_links(next_url)
          results.concat(Array(body))
          next_url = next_link(link_header)
        end

        results
      end

      def get_json(url)
        key = "github:#{url}"
        @cache.fetch_or_store('github', key) { @http.get_json(url, github_headers) }
      end

      def get_json_with_links(url)
        uri = URI(url)
        raise "Unexpected GitHub host #{uri.host}" unless uri.host == HOST

        request = Net::HTTP::Get.new(uri)
        github_headers.each { |key, value| request[key] = value if value && !value.to_s.empty? }

        response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 15, read_timeout: 15) do |http|
          http.request(request)
        end

        unless response.is_a?(Net::HTTPSuccess)
          raise "GitHub request failed with #{response.code}"
        end

        [JSON.parse(response.body), response['link']]
      end

      def next_link(header)
        return nil unless header

        header.split(',').each do |entry|
          url, rel = entry.split(';').map(&:strip)
          next unless rel == 'rel="next"'

          uri = URI(url.delete_prefix('<').delete_suffix('>'))
          return uri.to_s if uri.host == HOST
        end

        nil
      end

      def github_headers
        {
          'Accept' => 'application/vnd.github+json',
          'User-Agent' => 'dependency-risk-analyzer',
          'Authorization' => @token && "Bearer #{@token}"
        }
      end
    end
  end
end
