require_relative 'test_helper'

class DirectDependencyDetectorTest < Minitest::Test
  def test_package_json_reads_dependencies_and_optional_dependencies
    detector = DependencyRisk::Graph::DirectDependencyDetector.new(nil)

    dependencies = detector.parse_package_json(fixture_path('package.json'))

    assert_equal %w[chokidar react react-dom], dependencies.map(&:name).sort
    assert dependencies.all?(&:direct)
  end

  def test_gemfile_skips_development_and_test_groups
    Dir.mktmpdir do |dir|
      gemfile = File.join(dir, 'Gemfile')
      File.write(gemfile, <<~GEMFILE)
        source 'https://rubygems.org'
        gem 'rack'

        group :development do
          gem 'rubocop'
        end

        group :test do
          gem 'minitest'
        end
      GEMFILE

      dependencies = DependencyRisk::Graph::DirectDependencyDetector.new(dir).direct_dependencies

      assert_equal ['rack'], dependencies.map(&:name)
    end
  end
end
