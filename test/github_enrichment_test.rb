require_relative 'test_helper'

class GithubEnrichmentTest < Minitest::Test
  def test_enrich_uses_repository_summary_without_crawling_issue_pages
    github = github_enricher
    package = DependencyRisk::Models::Package.new(name: 'rack', type: 'gem', version: '3.2.0')
    package.repository_url = 'https://github.com/rack/rack'

    github.define_singleton_method(:open_pr_count) { |_owner, _repo| 4 }
    github.define_singleton_method(:repository_info) { |_owner, _repo| { 'open_issues_count' => 14 } }
    github.define_singleton_method(:last_commit_date) { |_owner, _repo, _info| '2026-06-11T19:33:55Z' }

    assert github.enrich!(package)
    assert_equal(
      {
        'issues' => 10,
        'prs' => 4,
        'last_commit' => '2026-06-11T19:33:55Z'
      },
      package.github
    )
  end

  def test_last_page_number_reads_github_link_header
    github = github_enricher
    header = [
      '<https://api.github.com/repos/rack/rack/pulls?state=open&per_page=1&page=2>; rel="next"',
      '<https://api.github.com/repos/rack/rack/pulls?state=open&per_page=1&page=25>; rel="last"'
    ].join(', ')

    assert_equal 25, github.send(:last_page_number, header)
  end

  def test_enrich_all_uses_graphql_for_repository_health
    github = github_enricher
    packages = 2.times.map do
      DependencyRisk::Models::Package.new(name: 'rack', type: 'gem', version: '3.2.0').tap do |package|
        package.repository_url = 'https://github.com/rack/rack'
      end
    end
    calls = []

    github.define_singleton_method(:post_graphql) do |query|
      calls << query
      {
        'data' => {
          'r0' => {
            'issues' => { 'totalCount' => 13 },
            'pullRequests' => { 'totalCount' => 20 },
            'defaultBranchRef' => {
              'target' => {
                'history' => {
                  'nodes' => [{ 'committedDate' => '2026-06-11T19:33:55Z' }]
                }
              }
            },
            'pushedAt' => '2026-06-12T10:00:00Z'
          }
        }
      }
    end

    assert github.enrich_all!(packages)
    assert_equal 1, calls.count
    packages.each do |package|
      assert_equal(
        {
          'issues' => 13,
          'prs' => 20,
          'last_commit' => '2026-06-11T19:33:55Z'
        },
        package.github
      )
    end
  end

  private

  def github_enricher
    previous = ENV['GITHUB_TOKEN']
    ENV['GITHUB_TOKEN'] = 'test-token'
    DependencyRisk::Enrichment::Github.new(
      cache: DependencyRisk::Cache.new(dir: Dir.mktmpdir, force: true)
    )
  ensure
    previous.nil? ? ENV.delete('GITHUB_TOKEN') : ENV['GITHUB_TOKEN'] = previous
  end
end
