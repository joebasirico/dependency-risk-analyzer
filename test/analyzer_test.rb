require_relative 'test_helper'

class AnalyzerTest < Minitest::Test
  def test_scan_merges_sbom_grype_license_and_risk
    Dir.mktmpdir do |dir|
      output = File.join(dir, 'report')
      options = {
        directory: nil,
        sbom: fixture_path('syft.json'),
        grype: true,
        grype_path: fixture_path('grype_matches.json'),
        scan_depth: 0,
        enrich: false,
        nvd: false,
        cache_dir: File.join(dir, 'cache'),
        force: false,
        license_dir: File.expand_path('../licenses', __dir__),
        output: output,
        format: %w[terminal json csv]
      }

      writer = DependencyRisk::Analyzer.new(options).scan
      report = writer.to_h

      assert_equal 4, report['summary']['package_count']
      assert_equal 3, report['summary']['vulnerable_package_count']
      assert_equal 1, report['summary']['vulnerabilities']['critical']
      assert report['packages'].any? { |package| package['name'] == 'unknown-license' && package['license_result']['status'] == 'unknown' }
    end
  end
end
