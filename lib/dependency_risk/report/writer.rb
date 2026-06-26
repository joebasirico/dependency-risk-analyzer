require 'fileutils'
require 'json'

module DependencyRisk
  module Report
    class Writer
      def initialize(packages:, warnings: [], metadata: {})
        @packages = packages
        @warnings = warnings
        @metadata = metadata
      end

      def to_h
        {
          'metadata' => @metadata,
          'summary' => summary,
          'warnings' => @warnings,
          'packages' => sorted_packages.map(&:to_h)
        }
      end

      def write_json(path)
        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, JSON.pretty_generate(to_h))
      end

      def write_csv(path)
        require 'csv'

        FileUtils.mkdir_p(File.dirname(path))
        CSV.open(path, 'wb') do |csv|
          csv << %w[name type version direct risk_score license_status critical high medium low vulnerabilities introduced_by factors]
          sorted_packages.each do |package|
            counts = package.vulnerability_counts
            csv << [
              package.name,
              package.type,
              package.version,
              package.direct,
              package.risk_score,
              package.license_result && package.license_result['status'],
              counts['critical'],
              counts['high'],
              counts['medium'],
              counts['low'],
              package.vulnerabilities.map(&:id).uniq.join(';'),
              package.introduced_by.join(';'),
              package.risk_factors.join('; ')
            ]
          end
        end
      rescue LoadError => e
        raise e unless e.path == 'csv'

        raise 'CSV output requires the csv gem. Run bin/setup with the same Ruby used to run bin/dependency-risk.'
      end

      def terminal
        lines = []
        s = summary
        lines << "Dependency Risk Analysis"
        lines << "Packages: #{s['package_count']}  Vulnerable: #{s['vulnerable_package_count']}  High risk: #{s['high_risk_package_count']}"
        lines << "Vulnerabilities: C=#{s['vulnerabilities']['critical']} H=#{s['vulnerabilities']['high']} M=#{s['vulnerabilities']['medium']} L=#{s['vulnerabilities']['low']}"
        lines << ''

        if @warnings.any?
          lines << 'Warnings:'
          @warnings.each { |warning| lines << "  - #{warning}" }
          lines << ''
        end

        top = sorted_packages.select { |package| package.risk_score.positive? }.first(20)
        if top.empty?
          lines << 'No package risk factors found.'
        else
          lines << 'Top Risk Packages:'
          top.each do |package|
            vuln_ids = package.vulnerabilities.map(&:id).uniq
            lines << "  - #{package.type} #{package.name} #{package.version} risk=#{package.risk_score} direct=#{package.direct}"
            lines << "    CVEs: #{vuln_ids.join(', ')}" unless vuln_ids.empty?
            lines << "    Introduced by: #{package.introduced_by.join(', ')}" unless package.introduced_by.empty?
            lines << "    Factors: #{package.risk_factors.join('; ')}" unless package.risk_factors.empty?
          end
        end

        lines.join("\n")
      end

      private

      def sorted_packages
        @packages.sort_by { |package| [-package.risk_score.to_i, package.type, package.name, package.version.to_s] }
      end

      def summary
        counts = Hash.new(0)
        @packages.each do |package|
          package.vulnerabilities.each { |vulnerability| counts[vulnerability.severity] += 1 }
        end

        {
          'package_count' => @packages.count,
          'direct_package_count' => @packages.count(&:direct),
          'vulnerable_package_count' => @packages.count { |package| package.vulnerabilities.any? },
          'high_risk_package_count' => @packages.count { |package| package.risk_score.to_i >= 70 },
          'vulnerabilities' => {
            'critical' => counts['critical'],
            'high' => counts['high'],
            'medium' => counts['medium'],
            'low' => counts['low'],
            'unknown' => counts['unknown']
          }
        }
      end
    end
  end
end
