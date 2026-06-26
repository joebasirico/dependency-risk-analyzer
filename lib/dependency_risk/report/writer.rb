require 'fileutils'
require 'date'
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
          lines.concat(risk_table(colors, top))
        end

        github_packages = sorted_packages.select { |package| github_health?(package) }.first(20)
        if github_packages.any?
          lines << ''
          lines << colors.bold.call('GitHub Repository Health:')
          lines.concat(github_health_table(colors, github_packages))
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

      def risk_table(colors, packages)
        rows = packages.map do |package|
          [
            risk_cell(colors, package.risk_score),
            package_label(package),
            package.version.to_s,
            package.direct ? 'yes' : 'no',
            vulnerability_counts_cell(colors, package),
            cve_count_cell(colors, package),
            factors_cell(package)
          ]
        end

        table_lines(colors, ['Risk', 'Package', 'Version', 'Direct', 'Vulns', 'CVEs', 'Factors'], rows, right: [5])
      end

      def risk_cell(colors, score)
        style = risk_style(colors, score)
        "#{style.call(risk_icon(score))} #{style.call(score.to_i.to_s)}"
      end

      def vulnerability_counts_cell(colors, package)
        counts = package.vulnerability_counts
        parts = [
          ['critical', 'C', colors.magenta],
          ['high', 'H', colors.red],
          ['medium', 'M', colors.yellow],
          ['low', 'L', colors.blue]
        ].filter_map do |severity, label, style|
          count = counts[severity].to_i
          style.call("#{label}=#{count}") if count.positive?
        end

        parts.empty? ? colors.green.call('none') : parts.join(' ')
      end

      def cve_count_cell(colors, package)
        count = package.vulnerabilities.map(&:id).uniq.count
        style = count.positive? ? colors.red : colors.green
        style.call(count.to_s)
      end

      def factors_cell(package)
        package.risk_factors.empty? ? 'none' : package.risk_factors.join('; ')
      end

      def github_health?(package)
        github = package.github || {}
        github.key?('issues') || github.key?('prs') || github.key?('last_commit')
      end

      def github_health_table(colors, packages)
        rows = packages.map do |package|
          github_health_row(colors, package)
        end

        table_lines(colors, ['Package', 'Version', 'Issues', 'PRs', 'Last Commit', 'Age'], rows, right: [2, 3, 5])
      end

      def github_health_row(colors, package)
        github = package.github || {}
        commit_date, commit_age, age_days = github_commit_parts(github['last_commit'])
        [
          package_label(package),
          package.version.to_s,
          github_count(colors, github['issues'], warning_over: 20),
          github_count(colors, github['prs'], warning_over: 20),
          github_commit_value(colors, commit_date, age_days),
          github_commit_value(colors, commit_age, age_days)
        ]
      end

      def github_count(colors, value, warning_over: nil)
        return colors.cyan.call('unknown') if value.nil?

        count = value.to_i
        style = warning_over && count > warning_over ? colors.yellow : colors.blue
        style.call(count.to_s)
      end

      def github_commit_parts(value)
        return ['unknown', 'unknown', nil] if value.nil? || value.to_s.empty?

        date = DateTime.parse(value.to_s)
        days_old = (DateTime.now - date).to_i
        [date.strftime('%Y-%m-%d'), "#{days_old}d", days_old]
      rescue ArgumentError
        [value.to_s, 'unknown', nil]
      end

      def github_commit_value(colors, value, days_old)
        style = if days_old.nil?
                  colors.cyan
                elsif days_old > 365
                  colors.red
                elsif days_old > 180
                  colors.yellow
                else
                  colors.green
                end
        style.call(value)
      end

      def package_label(package)
        "#{package.type}/#{package.name}"
      end

      def table_lines(colors, headers, rows, right: [])
        widths = headers.each_index.map do |index|
          ([headers[index]] + rows.map { |row| row[index] }).map { |cell| visible_width(cell) }.max
        end

        [
          '  ' + format_table_row(headers.map { |header| colors.bold.call(header) }, widths, right),
          '  ' + widths.map { |width| '-' * width }.join('  '),
          *rows.map { |row| '  ' + format_table_row(row, widths, right) }
        ]
      end

      def format_table_row(row, widths, right)
        row.each_with_index.map do |cell, index|
          align = right.include?(index) ? :right : :left
          pad_cell(cell, widths[index], align)
        end.join('  ')
      end

      def pad_cell(value, width, align)
        text = value.to_s
        padding = [width - visible_width(text), 0].max
        align == :right ? "#{' ' * padding}#{text}" : "#{text}#{' ' * padding}"
      end

      def visible_width(value)
        value.to_s.gsub(/\e\[[\d;]*m/, '').length
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
