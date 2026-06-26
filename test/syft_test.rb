require_relative 'test_helper'

class SyftTest < Minitest::Test
  def test_packages_from_syft_json_normalizes_artifacts
    data = JSON.parse(File.read(fixture_path('syft.json')))

    packages = DependencyRisk::Sbom::Syft.packages_from_json(data)

    assert_equal 4, packages.count
    rack = packages.find { |package| package.name == 'rack' && package.version == '2.2.6' }
    assert_equal 'gem:rack:2.2.6', rack.key
    assert_equal ['MIT'], rack.licenses
  end
end
