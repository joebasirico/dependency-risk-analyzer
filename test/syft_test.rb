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

  def test_run_syft_ignores_stderr_progress_when_parsing_json
    syft = DependencyRisk::Sbom::Syft.new(directory: FIXTURE_DIR)
    syft.define_singleton_method(:executable?) { |_command| true }
    status = Struct.new(:success?).new(true)
    original = Open3.method(:capture3)
    captured_args = nil

    Open3.define_singleton_method(:capture3) do |*args|
      captured_args = args
      [File.read(fixture_path('syft.json')), '[0000] cataloging packages', status]
    end

    assert_equal 4, syft.packages.count
    assert_equal ['syft', '-o', 'syft-json', File.expand_path(FIXTURE_DIR)], captured_args
  ensure
    Open3.define_singleton_method(:capture3, original) if original
  end
end
