require_relative 'test_helper'
require 'dependency_risk/cli'

class CliTest < Minitest::Test
  def test_scan_cli_writes_json_and_csv_from_fixtures
    Dir.mktmpdir do |dir|
      output = File.join(dir, 'fixture-report')
      argv = [
        'scan',
        '--sbom', fixture_path('syft.json'),
        '--grype', fixture_path('grype_matches.json'),
        '--format', 'json,csv',
        '--output', output
      ]

      status = DependencyRisk::CLI.new(argv).run

      assert_equal 0, status
      assert File.file?("#{output}.json")
      assert File.file?("#{output}.csv")
    end
  end

  def test_scan_cli_supports_forced_color
    Dir.mktmpdir do |dir|
      output = File.join(dir, 'fixture-report')
      argv = [
        'scan',
        '--sbom', fixture_path('syft.json'),
        '--grype', fixture_path('grype_matches.json'),
        '--format', 'terminal',
        '--color', 'always',
        '--output', output
      ]

      rendered = capture_stdout do
        assert_equal 0, DependencyRisk::CLI.new(argv).run
      end

      assert_includes rendered, "\e["
      assert_includes rendered, 'Dependency Risk Analysis'
    end
  end
end
