module DependencyRisk
  module Models
    class Package
      attr_accessor :name, :type, :version, :purl, :cpes, :metadata, :licenses,
                    :description, :homepage, :repository_url, :latest_version,
                    :current_release_published_at, :latest_release_published_at,
                    :sourcerank, :github, :vulnerabilities, :dependencies,
                    :direct, :introduced_by, :license_result, :risk_score,
                    :risk_factors

      def initialize(name:, type:, version: nil, purl: nil, cpes: [], metadata: {},
                     licenses: [], direct: false)
        @name = name.to_s
        @type = type.to_s
        @version = version
        @purl = purl
        @cpes = Array(cpes).compact
        @metadata = metadata || {}
        @licenses = normalize_licenses(licenses)
        @description = nil
        @homepage = nil
        @repository_url = nil
        @latest_version = nil
        @current_release_published_at = nil
        @latest_release_published_at = nil
        @sourcerank = nil
        @github = {}
        @vulnerabilities = []
        @dependencies = []
        @direct = direct
        @introduced_by = []
        @license_result = nil
        @risk_score = 0
        @risk_factors = []
      end

      def self.from_syft_artifact(artifact)
        new(
          name: artifact['name'],
          type: artifact['type'],
          version: artifact['version'],
          purl: artifact['purl'],
          cpes: artifact['cpes'],
          metadata: artifact['metadata'] || {},
          licenses: artifact['licenses']
        )
      end

      def key
        [type, name, version].map(&:to_s).join(':')
      end

      def package_key
        [type, name].map(&:to_s).join(':')
      end

      def same_package?(other)
        type == other.type && name == other.name
      end

      def add_vulnerability(vulnerability)
        vulnerabilities << vulnerability unless vulnerabilities.any? { |v| v.identity == vulnerability.identity }
      end

      def vulnerability_counts
        counts = Hash.new(0)
        vulnerabilities.each { |v| counts[v.severity] += 1 }
        counts
      end

      def to_h
        {
          'name' => name,
          'type' => type,
          'version' => version,
          'purl' => purl,
          'cpes' => cpes,
          'licenses' => licenses,
          'direct' => direct,
          'introduced_by' => introduced_by,
          'dependencies' => dependencies,
          'description' => description,
          'homepage' => homepage,
          'repository_url' => repository_url,
          'latest_version' => latest_version,
          'current_release_published_at' => serialize_time(current_release_published_at),
          'latest_release_published_at' => serialize_time(latest_release_published_at),
          'sourcerank' => sourcerank,
          'github' => github,
          'license_result' => license_result,
          'vulnerabilities' => vulnerabilities.map(&:to_h),
          'risk_score' => risk_score,
          'risk_factors' => risk_factors
        }
      end

      private

      def normalize_licenses(raw)
        Array(raw).flat_map do |license|
          if license.is_a?(Hash)
            license['value'] || license['license'] || license['spdxExpression']
          else
            license
          end
        end.compact.map(&:to_s).map(&:strip).reject(&:empty?).uniq
      end

      def serialize_time(value)
        value.respond_to?(:iso8601) ? value.iso8601 : value
      end
    end
  end
end
