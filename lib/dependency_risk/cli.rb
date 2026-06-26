require 'optparse'
require 'dependency_risk'

module DependencyRisk
  class CLI
    DEFAULT_OPTIONS = {
      cache_dir: '.dependency-risk-cache',
      force: false,
      format: %w[terminal],
      color: 'auto',
      grype: true,
      grype_path: nil,
      enrich: false,
      nvd: false,
      scan_depth: 0,
      license_dir: Analyzer::DEFAULT_LICENSE_DIR,
      output: 'dependency-risk-report'
    }.freeze

    def initialize(argv)
      @argv = argv.dup
    end

    def run
      command = @argv.shift
      case command
      when 'scan'
        run_scan
      when 'dependency'
        run_dependency
      when 'help', nil
        puts help
        0
      else
        warn "Unknown command: #{command}"
        puts help
        2
      end
    rescue OptionParser::ParseError, ArgumentError => e
      warn e.message
      2
    rescue StandardError => e
      warn e.message
      1
    end

    private

    def run_scan
      options = DEFAULT_OPTIONS.merge(directory: nil, sbom: nil)
      parser = OptionParser.new do |opts|
        opts.banner = 'usage: dependency-risk scan [options]'
        opts.on('--directory DIR', 'Directory to scan with Syft/Grype') { |value| options[:directory] = value }
        opts.on('--sbom FILE', 'Existing Syft JSON SBOM to analyze') { |value| options[:sbom] = value }
        opts.on('--grype FILE', 'Existing Grype JSON result to use') { |value| options[:grype_path] = value }
        opts.on('--no-grype', 'Skip Grype vulnerability analysis') { options[:grype] = false }
        opts.on('--scan-depth N', Integer, 'Resolve transitive graph via Libraries.io') { |value| options[:scan_depth] = value }
        opts.on('--enrich', 'Enrich packages with Libraries.io and GitHub metadata') { options[:enrich] = true }
        opts.on('--include-nvd', 'Add NVD vulnerability enrichment') { options[:nvd] = true }
        opts.on('--license-dir DIR', 'Directory containing license policy files') { |value| options[:license_dir] = value }
        opts.on('--cache-dir DIR', 'Cache directory') { |value| options[:cache_dir] = value }
        opts.on('--force', 'Refresh cached remote API responses') { options[:force] = true }
        opts.on('--format LIST', 'terminal,json,csv') { |value| options[:format] = value.split(',').map(&:strip) }
        opts.on('--color MODE', 'Color terminal output: auto, always, never') { |value| options[:color] = value }
        opts.on('--output BASE', 'Output base path for JSON/CSV') { |value| options[:output] = value }
        opts.on('--help', 'Show help') do
          puts opts
          exit 0
        end
      end
      parser.parse!(@argv)

      raise ArgumentError, 'Provide --directory or --sbom' unless options[:directory] || options[:sbom]

      writer = Analyzer.new(options).scan
      emit(writer, options)
      0
    end

    def run_dependency
      options = DEFAULT_OPTIONS.merge(name: nil, type: nil, version: nil, cpe: nil, grype: false)
      parser = OptionParser.new do |opts|
        opts.banner = 'usage: dependency-risk dependency [options]'
        opts.on('--name NAME', 'Dependency name') { |value| options[:name] = value }
        opts.on('--type TYPE', 'Package type such as gem, npm, python') { |value| options[:type] = value }
        opts.on('--version VERSION', 'Installed version') { |value| options[:version] = value }
        opts.on('--cpe CPE', 'CPE to query through NVD') { |value| options[:cpe] = value }
        opts.on('--enrich', 'Enrich with Libraries.io and GitHub metadata') { options[:enrich] = true }
        opts.on('--include-nvd', 'Add NVD vulnerability enrichment') { options[:nvd] = true }
        opts.on('--license-dir DIR', 'Directory containing license policy files') { |value| options[:license_dir] = value }
        opts.on('--cache-dir DIR', 'Cache directory') { |value| options[:cache_dir] = value }
        opts.on('--force', 'Refresh cached remote API responses') { options[:force] = true }
        opts.on('--format LIST', 'terminal,json,csv') { |value| options[:format] = value.split(',').map(&:strip) }
        opts.on('--color MODE', 'Color terminal output: auto, always, never') { |value| options[:color] = value }
        opts.on('--output BASE', 'Output base path for JSON/CSV') { |value| options[:output] = value }
        opts.on('--help', 'Show help') do
          puts opts
          exit 0
        end
      end
      parser.parse!(@argv)

      raise ArgumentError, 'Provide --name and --type, or provide --cpe' unless (options[:name] && options[:type]) || options[:cpe]
      options[:name] ||= options[:cpe]
      options[:type] ||= 'cpe'

      writer = Analyzer.new(options).dependency
      emit(writer, options)
      0
    end

    def emit(writer, options)
      formats = options[:format]
      puts writer.terminal(color: color?(options[:color])) if formats.include?('terminal')
      writer.write_json("#{options[:output]}.json") if formats.include?('json')
      writer.write_csv("#{options[:output]}.csv") if formats.include?('csv')
    end

    def color?(mode)
      case mode
      when 'always'
        true
      when 'never'
        false
      when 'auto'
        $stdout.tty? && !ENV.key?('NO_COLOR')
      else
        raise ArgumentError, 'Color mode must be auto, always, or never'
      end
    end

    def help
      <<~HELP
        dependency-risk #{VERSION}

        Commands:
          scan        Analyze a directory or existing Syft SBOM
          dependency  Analyze one dependency or CPE

        Examples:
          dependency-risk scan --directory .
          dependency-risk scan --sbom syft.json --grype grype.json --format terminal,json,csv
          dependency-risk scan --directory . --scan-depth 2 --enrich --include-nvd
          dependency-risk dependency --name rack --type gem --version 2.2.6 --enrich
      HELP
    end
  end
end
