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
end
