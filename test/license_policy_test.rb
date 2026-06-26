require_relative 'test_helper'

class LicensePolicyTest < Minitest::Test
  def test_license_policy_marks_rejected_license
    package = DependencyRisk::Models::Package.new(name: 'bad', type: 'gem', licenses: ['GPL'])
    policy = DependencyRisk::Policy::LicensePolicy.new(directory: File.expand_path('../licenses', __dir__))

    result = policy.evaluate(package)

    assert_equal 'rejected', result['status']
    assert_includes result['findings'].join(' '), 'GPL'
  end

  def test_license_policy_marks_missing_license_unknown
    package = DependencyRisk::Models::Package.new(name: 'unknown', type: 'npm')
    policy = DependencyRisk::Policy::LicensePolicy.new(directory: File.expand_path('../licenses', __dir__))

    result = policy.evaluate(package)

    assert_equal 'unknown', result['status']
  end
end
