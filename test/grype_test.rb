require_relative 'test_helper'

class GrypeTest < Minitest::Test
  def test_attach_vulnerabilities_uses_exact_package_version
    packages = [
      DependencyRisk::Models::Package.new(name: 'rack', type: 'gem', version: '2.2.6'),
      DependencyRisk::Models::Package.new(name: 'rack', type: 'gem', version: '2.2.7')
    ]
    data = JSON.parse(File.read(fixture_path('grype_matches.json')))
    vulnerabilities = DependencyRisk::Scanners::Grype.vulnerabilities_from_json(data)

    unmatched = DependencyRisk::Scanners::Grype.attach!(packages, vulnerabilities)

    assert_equal ['CVE-ONE'], packages[0].vulnerabilities.map(&:id)
    assert_equal ['CVE-TWO'], packages[1].vulnerabilities.map(&:id)
    assert_equal ['CVE-THREE'], unmatched.map(&:id)
  end

  def test_run_grype_ignores_stderr_progress_when_parsing_json
    grype = DependencyRisk::Scanners::Grype.new(target: FIXTURE_DIR)
    grype.define_singleton_method(:executable?) { |_command| true }
    status = Struct.new(:success?).new(true)
    original = Open3.method(:capture3)
    captured_args = nil

    Open3.define_singleton_method(:capture3) do |*args|
      captured_args = args
      [File.read(fixture_path('grype_matches.json')), '[0000] loading vulnerability DB', status]
    end

    assert_equal 3, grype.vulnerabilities.count
    assert_equal ['grype', File.expand_path(FIXTURE_DIR), '-o', 'json', '--add-cpes-if-none'], captured_args
  ensure
    Open3.define_singleton_method(:capture3, original) if original
  end
end
