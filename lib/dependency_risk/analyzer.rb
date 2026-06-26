require 'fileutils'
require 'time'

module DependencyRisk
  class Analyzer
    DEFAULT_LICENSE_DIR = File.expand_path('../../licenses', __dir__)

    def initialize(options)
      @options = options
      @warnings = []
      @cache = Cache.new(dir: options[:cache_dir], force: options[:force])
    end

    def scan
      packages = load_packages
      mark_direct_dependencies(packages)
      attach_grype_vulnerabilities(packages) if @options[:grype]
      apply_license_policy(packages)
      enrich_packages(packages) if @options[:enrich]
      enrich_nvd(packages) if @options[:nvd]
      expand_graph(packages) if @options[:scan_depth].to_i.positive?
      score_packages(packages)

      Report::Writer.new(packages: packages, warnings: @warnings, metadata: metadata)
    end

    def dependency
      package = Models::Package.new(
        name: @options[:name],
        type: @options[:type],
        version: @options[:version],
        cpes: Array(@options[:cpe]).compact,
        direct: true
      )

      packages = [package]
      apply_license_policy(packages)
      enrich_packages(packages) if @options[:enrich]
      enrich_nvd(packages) if @options[:nvd] || package.cpes.any?
      score_packages(packages)

      Report::Writer.new(packages: packages, warnings: @warnings, metadata: metadata.merge('mode' => 'dependency'))
    end

    private

    def load_packages
      Sbom::Syft.new(directory: @options[:directory], sbom_path: @options[:sbom]).packages
    rescue StandardError => e
      raise "Unable to load SBOM data: #{e.message}"
    end

    def mark_direct_dependencies(packages)
      return unless @options[:directory]

      Graph::DirectDependencyDetector.new(@options[:directory]).mark_direct!(packages)
    end

    def attach_grype_vulnerabilities(packages)
      vulnerabilities = Scanners::Grype.new(
        target: @options[:directory],
        grype_path: @options[:grype_path],
        sbom_path: @options[:sbom]
      ).vulnerabilities
      unmatched = Scanners::Grype.attach!(packages, vulnerabilities)
      @warnings << "#{unmatched.count} Grype vulnerabilities did not match an SBOM package" if unmatched.any?
    rescue StandardError => e
      @warnings << "Grype skipped: #{e.message}"
    end

    def apply_license_policy(packages)
      policy = Policy::LicensePolicy.new(directory: @options[:license_dir])
      packages.each { |package| policy.evaluate(package) }
    end

    def enrich_packages(packages)
      libraries_io = Enrichment::LibrariesIo.new(cache: @cache)
      unless libraries_io.available?
        @warnings << 'Libraries.io enrichment skipped: LIBRARIES_IO_API_KEY is not configured'
        return
      end

      github = Enrichment::Github.new(cache: @cache)
      packages.each { |package| libraries_io.enrich!(package) }
      github.enrich_all!(packages)
    end

    def enrich_nvd(packages)
      nvd = Enrichment::Nvd.new(cache: @cache)
      packages.each { |package| nvd.enrich!(package) }
    end

    def expand_graph(packages)
      libraries_io = Enrichment::LibrariesIo.new(cache: @cache)
      unless libraries_io.available?
        @warnings << 'Dependency graph expansion skipped: LIBRARIES_IO_API_KEY is not configured'
        return
      end

      Graph::LibrariesIoGraph.new(client: libraries_io).expand!(packages, max_depth: @options[:scan_depth])
    end

    def score_packages(packages)
      scorer = Risk::Scorer.new
      packages.each { |package| scorer.score!(package) }
    end

    def metadata
      {
        'generated_at' => Time.now.utc.iso8601,
        'tool' => "dependency-risk-analyzer #{VERSION}",
        'directory' => @options[:directory],
        'sbom' => @options[:sbom],
        'grype' => @options[:grype_path],
        'scan_depth' => @options[:scan_depth],
        'enrichment' => @options[:enrich],
        'nvd' => @options[:nvd]
      }
    end
  end
end
