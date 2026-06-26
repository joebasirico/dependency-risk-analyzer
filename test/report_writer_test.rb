require_relative 'test_helper'

class ReportWriterTest < Minitest::Test
  def test_terminal_output_includes_icons_without_color
    package = risky_package
    writer = DependencyRisk::Report::Writer.new(packages: [package], warnings: ['scanner skipped'])

    output = writer.terminal(color: false)

    assert_includes output, '◆ Dependency Risk Analysis'
    assert_includes output, '⚠ Warnings:'
    assert_match(/Risk\s+Package\s+Version\s+Direct\s+Vulns\s+CVEs\s+Factors/, output)
    assert_match(/▲ 40\s+gem\/rack\s+2\.2\.6\s+yes\s+H=1\s+1\s+1 high vulnerability/, output)
    refute_includes output, "\e["
  end

  def test_terminal_output_can_include_color
    writer = DependencyRisk::Report::Writer.new(packages: [risky_package])

    output = writer.terminal(color: true)

    assert_includes output, "\e["
    assert_includes output, '40'
  end

  def test_terminal_output_includes_github_repository_health
    package = risky_package
    package.github = {
      'issues' => 3,
      'prs' => 2,
      'last_commit' => '2026-06-01T12:00:00Z'
    }
    writer = DependencyRisk::Report::Writer.new(packages: [package])

    output = writer.terminal(color: false)

    assert_includes output, 'GitHub Repository Health:'
    assert_match(/Package\s+Version\s+Issues\s+PRs\s+Last Commit\s+Age/, output)
    assert_match(/gem\/rack\s+2\.2\.6\s+3\s+2\s+2026-06-01\s+\d+d/, output)
  end

  private

  def risky_package
    package = DependencyRisk::Models::Package.new(name: 'rack', type: 'gem', version: '2.2.6', direct: true)
    package.risk_score = 40
    package.risk_factors = ['1 high vulnerability']
    package.add_vulnerability(
      DependencyRisk::Models::Vulnerability.new(
        id: 'CVE-ONE',
        source: 'grype',
        severity: 'high',
        package_name: 'rack',
        package_type: 'gem',
        package_version: '2.2.6'
      )
    )
    package
  end
end
