require 'json'
require 'open3'

module DependencyRisk
  module Scanners
    class Grype
      def self.vulnerabilities_from_json(data)
        Array(data.fetch('matches', [])).map do |match|
          Models::Vulnerability.from_grype_match(match)
        end
      end

      def self.attach!(packages, vulnerabilities)
        by_key = packages.each_with_object({}) { |pkg, memo| memo[pkg.key] = pkg }
        unmatched = []

        vulnerabilities.each do |vulnerability|
          key = [vulnerability.package_type, vulnerability.package_name,
                 vulnerability.package_version].map(&:to_s).join(':')
          package = by_key[key]
          package ? package.add_vulnerability(vulnerability) : unmatched << vulnerability
        end

        unmatched
      end

      def initialize(target: nil, grype_path: nil, sbom_path: nil)
        @target = target
        @grype_path = grype_path
        @sbom_path = sbom_path
      end

      def vulnerabilities
        self.class.vulnerabilities_from_json(load_json)
      end

      def load_json
        if @grype_path
          JSON.parse(File.read(expanded_file(@grype_path)))
        else
          run_grype
        end
      end

      private

      def run_grype
        raise 'grype executable not found' unless executable?('grype')

        target = if @sbom_path
                   "sbom:#{File.expand_path(@sbom_path)}"
                 elsif @target
                   File.expand_path(@target)
                 else
                   raise 'Target directory or SBOM is required for Grype'
                 end

        stdout, stderr, status = Open3.capture3('grype', target, '-o', 'json', '--add-cpes-if-none')
        raise "Grype execution failed: #{stderr.empty? ? stdout : stderr}" unless status.success?

        JSON.parse(stdout)
      end

      def expanded_file(path)
        expanded = File.expand_path(path)
        raise "File #{expanded} does not exist" unless File.file?(expanded)

        expanded
      end

      def executable?(command)
        _stdout, status = Open3.capture2('which', command)
        status.success?
      end
    end
  end
end
