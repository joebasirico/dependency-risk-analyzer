require_relative 'test_helper'

class ReportWriterTest < Minitest::Test
  def test_terminal_output_includes_icons_without_color
    package = risky_package
    writer = DependencyRisk::Report::Writer.new(packages: [package], warnings: ['scanner skipped'])

    output = writer.terminal(color: false)

    assert_includes output, '◆ Dependency Risk Analysis'
    assert_includes output, '⚠ Warnings:'
    assert_includes output, '▲ gem rack 2.2.6'
    assert_includes output, '✚ CVEs: CVE-ONE'
    refute_includes output, "\e["
  end

  def test_terminal_output_can_include_color
    writer = DependencyRisk::Report::Writer.new(packages: [risky_package])

    output = writer.terminal(color: true)

    assert_includes output, "\e["
    assert_includes output, 'risk=40'
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
