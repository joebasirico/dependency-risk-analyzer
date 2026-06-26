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
        @token = Credentials.fetch('GITHUB_TOKEN') || Credentials.github_token
      end

      def enrich!(package)
        owner, repo = owner_repo(package.repository_url)
        return false unless owner && repo

        info = repository_info(owner, repo)
        open_prs = open_pr_count(owner, repo)
        package.github = {
          'issues' => open_issue_count(info, open_prs),
          'prs' => open_prs,
          'last_commit' => last_commit_date(owner, repo, info)
        }
        true
      rescue StandardError
        false
      end

      def enrich_all!(packages)
        targets = github_targets(packages)
        return false if targets.empty?

        health = @token ? graphql_health(targets.keys) : {}
        targets.each do |repo_key, repo_packages|
          data = health[repo_key]
          if data
            repo_packages.each { |package| package.github = data.dup }
          else
            repo_packages.each { |package| enrich!(package) }
          end
        end
        true
      rescue StandardError
        packages.each { |package| enrich!(package) if package.repository_url }
        false
      end

      def owner_repo(repository_url)
        return [nil, nil] unless repository_url

        match = repository_url.match(%r{github\.com[:/]([\w.\-]+)/([\w.\-]+?)(?:\.git)?(?:/|\z)})
        return [nil, nil] unless match

        [match[1], match[2]]
      end

      private

      def github_targets(packages)
        packages.each_with_object({}) do |package, targets|
          owner, repo = owner_repo(package.repository_url)
          next unless owner && repo

          (targets[[owner, repo]] ||= []) << package
        end
      end

      def open_issue_count(info, open_prs)
        open_items = info['open_issues_count'].to_i
        [open_items - open_prs.to_i, 0].max
      end

      def open_pr_count(owner, repo)
        paginated_count("#{BASE_URL}/repos/#{owner}/#{repo}/pulls?state=open&per_page=1")
      end

      def last_commit_date(owner, repo, info = nil)
        return info['pushed_at'] if info && info['pushed_at']

        commits = get_json("#{BASE_URL}/repos/#{owner}/#{repo}/commits?per_page=1")
        first = Array(commits).first
        first && first.dig('commit', 'author', 'date')
      end

      def repository_info(owner, repo)
        get_json("#{BASE_URL}/repos/#{owner}/#{repo}")
      end

      def paginated_count(url)
        key = "github-count:#{url}"
        @cache.fetch_or_store('github', key) { uncached_paginated_count(url) }
      end

      def uncached_paginated_count(url)
        body, link_header = get_json_with_links(url)
        last_page = last_page_number(link_header)
        return last_page if last_page

        Array(body).count
      end

      def graphql_health(repo_keys)
        repo_keys.each_slice(25).each_with_object({}) do |batch, results|
          query = graphql_query(batch)
          body = post_graphql(query)
          data = body['data'] || {}

          batch.each_with_index do |repo_key, index|
            repo = data["r#{index}"]
            next unless repo

            results[repo_key] = {
              'issues' => repo.dig('issues', 'totalCount').to_i,
              'prs' => repo.dig('pullRequests', 'totalCount').to_i,
              'last_commit' => graphql_last_commit(repo)
            }
          end
        end
      end

      def graphql_query(repo_keys)
        fields = repo_keys.each_with_index.map do |(owner, repo), index|
          <<~GRAPHQL
            r#{index}: repository(owner: #{JSON.generate(owner)}, name: #{JSON.generate(repo)}) {
              issues(states: OPEN) { totalCount }
              pullRequests(states: OPEN) { totalCount }
              defaultBranchRef {
                target {
                  ... on Commit {
                    history(first: 1) {
                      nodes { committedDate }
                    }
                  }
                }
              }
              pushedAt
            }
          GRAPHQL
        end.join("\n")

        "query DependencyRiskRepositoryHealth {\n#{fields}\n}"
      end

      def graphql_last_commit(repo)
        repo.dig('defaultBranchRef', 'target', 'history', 'nodes', 0, 'committedDate') || repo['pushedAt']
      end

      def post_graphql(query)
        uri = URI("#{BASE_URL}/graphql")
        request = Net::HTTP::Post.new(uri)
        github_headers.merge('Content-Type' => 'application/json').each do |key, value|
          request[key] = value if value && !value.to_s.empty?
        end
        request.body = JSON.generate('query' => query)

        response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 10, read_timeout: 10) do |http|
          http.request(request)
        end

        raise "GitHub GraphQL request failed with #{response.code}" unless response.is_a?(Net::HTTPSuccess)

        JSON.parse(response.body)
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

      def last_page_number(header)
        return nil unless header

        header.split(',').each do |entry|
          url, rel = entry.split(';').map(&:strip)
          next unless rel == 'rel="last"'

          uri = URI(url.delete_prefix('<').delete_suffix('>'))
          return URI.decode_www_form(uri.query.to_s).assoc('page')&.last&.to_i if uri.host == HOST
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
