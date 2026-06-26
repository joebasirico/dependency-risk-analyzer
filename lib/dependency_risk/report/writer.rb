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

      def terminal(color: false)
        lines = []
        s = summary
        colors = color ? Ansi.new : Ansi.disabled

        lines << "#{colors.cyan.call('◆')} #{colors.bold.call('Dependency Risk Analysis')}"
        lines << [
          "#{colors.blue.call('▣')} Packages: #{s['package_count']}",
          summary_count(colors, '▲', 'Vulnerable', s['vulnerable_package_count'], colors.yellow),
          summary_count(colors, '●', 'High risk', s['high_risk_package_count'], colors.red)
        ].join('  ')
        lines << [
          'Vulnerabilities:',
          severity_count(colors, 'critical', s['vulnerabilities']['critical']),
          severity_count(colors, 'high', s['vulnerabilities']['high']),
          severity_count(colors, 'medium', s['vulnerabilities']['medium']),
          severity_count(colors, 'low', s['vulnerabilities']['low'])
        ].join(' ')
        lines << ''

        if @warnings.any?
          lines << colors.yellow.call('⚠ Warnings:')
          @warnings.each { |warning| lines << "  #{colors.yellow.call('!')} #{warning}" }
          lines << ''
        end

        top = sorted_packages.select { |package| package.risk_score.positive? }.first(20)
        if top.empty?
          lines << colors.green.call('✓ No package risk factors found.')
        else
          lines << colors.bold.call('Top Risk Packages:')
          top.each do |package|
            vuln_ids = package.vulnerabilities.map(&:id).uniq
            style = risk_style(colors, package.risk_score)
            direct = package.direct ? 'yes' : 'no'
            risk = style.call("risk=#{package.risk_score}")
            lines << "  #{style.call(risk_icon(package.risk_score))} #{package.type} #{package.name} #{package.version}  #{risk}  direct=#{direct}"
            lines << "    #{colors.red.call('✚')} CVEs: #{vuln_ids.join(', ')}" unless vuln_ids.empty?
            lines << "    #{colors.cyan.call('↳')} Introduced by: #{package.introduced_by.join(', ')}" unless package.introduced_by.empty?
            lines << "    #{colors.yellow.call('•')} Factors: #{package.risk_factors.join('; ')}" unless package.risk_factors.empty?
          end
        end

        lines.join("\n")
      end

      private

      class Ansi
        CODES = {
          reset: 0,
          bold: 1,
          red: 31,
          green: 32,
          yellow: 33,
          blue: 34,
          magenta: 35,
          cyan: 36
        }.freeze

        def self.disabled
          new(enabled: false)
        end

        def initialize(enabled: true)
          @enabled = enabled
        end

        CODES.each_key do |name|
          define_method(name) do
            lambda { |text| paint(name, text) }
          end
        end

        def paint(name, text)
          return text unless @enabled

          "\e[#{CODES.fetch(name)}m#{text}\e[#{CODES.fetch(:reset)}m"
        end
      end

      def severity_count(colors, severity, count)
        style = case severity
                when 'critical' then colors.magenta
                when 'high' then colors.red
                when 'medium' then colors.yellow
                when 'low' then colors.blue
                else colors.cyan
                end
        label = severity[0].upcase
        style.call("#{label}=#{count}")
      end

      def summary_count(colors, icon, label, count, alert_style)
        style = count.to_i.positive? ? alert_style : colors.green
        "#{style.call(icon)} #{label}: #{count}"
      end

      def risk_icon(score)
        case score.to_i
        when 70..100
          '●'
        when 40..69
          '▲'
        when 15..39
          '◆'
        else
          '◇'
        end
      end

      def risk_style(colors, score)
        case score.to_i
        when 70..100
          colors.magenta
        when 40..69
          colors.red
        when 15..39
          colors.yellow
        else
          colors.blue
        end
      end

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
