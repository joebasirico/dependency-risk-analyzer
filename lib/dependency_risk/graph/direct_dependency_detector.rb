require 'json'

module DependencyRisk
  module Graph
    class DirectDependencyDetector
      def initialize(directory)
        @directory = File.expand_path(directory) if directory
      end

      def direct_dependencies
        return [] unless @directory && Dir.exist?(@directory)

        dependencies = []
        dependencies.concat(parse_package_json(File.join(@directory, 'package.json')))
        dependencies.concat(parse_gemfile(File.join(@directory, 'Gemfile')))
        dependencies.concat(parse_requirements(File.join(@directory, 'requirements.txt')))
        dependencies.uniq(&:package_key)
      end

      def mark_direct!(packages)
        direct_keys = direct_dependencies.map(&:package_key)
        packages.each do |package|
          next unless direct_keys.include?(package.package_key)

          package.direct = true
          package.introduced_by << package.key unless package.introduced_by.include?(package.key)
        end
      end

      def parse_package_json(path)
        return [] unless File.file?(path)

        data = JSON.parse(File.read(path))
        %w[dependencies optionalDependencies].flat_map do |key|
          data.fetch(key, {}).keys.map { |name| Models::Package.new(name: name, type: 'npm', direct: true) }
        end
      rescue JSON::ParserError
        []
      end

      def parse_gemfile(path)
        return [] unless File.file?(path)

        dependencies = []
        skip_depth = 0

        File.readlines(path).each do |line|
          stripped = line.strip
          next if stripped.empty? || stripped.start_with?('#')

          if stripped =~ /^group\s+(.+)\s+do\b/
            groups = Regexp.last_match(1)
            skip_depth += 1 if groups.include?('development') || groups.include?('test')
            next
          end

          if stripped == 'end'
            skip_depth -= 1 if skip_depth.positive?
            next
          end

          next if skip_depth.positive?

          match = stripped.match(/^gem\s+['"]([^'"]+)['"]/)
          dependencies << Models::Package.new(name: match[1], type: 'gem', direct: true) if match
        end

        dependencies
      end

      def parse_requirements(path)
        return [] unless File.file?(path)

        File.readlines(path).each_with_object([]) do |line, dependencies|
          stripped = line.strip
          next if stripped.empty? || stripped.start_with?('#')

          name, version = stripped.split(/[<>=!~]=?/, 2).map(&:strip)
          dependencies << Models::Package.new(name: name, type: 'python', version: version, direct: true)
        end
      end
    end
  end
end
