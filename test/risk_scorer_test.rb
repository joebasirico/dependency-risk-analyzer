require_relative 'test_helper'

class RiskScorerTest < Minitest::Test
  def test_scorer_combines_vulnerability_directness_and_license
    package = DependencyRisk::Models::Package.new(name: 'rack', type: 'gem', version: '2.2.6', direct: true)
    package.license_result = { 'status' => 'rejected', 'findings' => ['GPL is rejected'] }
    package.add_vulnerability(
      DependencyRisk::Models::Vulnerability.new(
        id: 'CVE-ONE',
        source: 'grype',
        severity: 'High',
        package_name: 'rack',
        package_type: 'gem',
        package_version: '2.2.6'
      )
    )

    DependencyRisk::Risk::Scorer.new.score!(package)

    assert_operator package.risk_score, :>=, 70
    assert_includes package.risk_factors, 'direct dependency exposure'
    assert_includes package.risk_factors, 'rejected license'
  end
end
