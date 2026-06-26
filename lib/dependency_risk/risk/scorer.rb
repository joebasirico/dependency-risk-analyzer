require 'date'

module DependencyRisk
  module Risk
    class Scorer
      SEVERITY_WEIGHTS = {
        'critical' => 40,
        'high' => 25,
        'medium' => 12,
        'low' => 4,
        'negligible' => 1,
        'unknown' => 2
      }.freeze

      def score!(package)
        score = 0
        factors = []

        package.vulnerability_counts.each do |severity, count|
          next if count.zero?

          points = SEVERITY_WEIGHTS.fetch(severity, 2) * count
          score += points
          factors << "#{count} #{severity} vulnerability#{'ies' if count != 1}"
        end

        if package.vulnerabilities.any? && package.direct
          score += 10
          factors << 'direct dependency exposure'
        elsif package.vulnerabilities.any? && package.introduced_by.any?
          score += 6
          factors << 'transitive dependency exposure with known direct introducer'
        end

        case package.license_result && package.license_result['status']
        when 'rejected'
          score += 35
          factors << 'rejected license'
        when 'caution'
          score += 15
          factors << 'license requires review'
        when 'unknown'
          score += 8
          factors << 'unknown license'
        end

        score += sourcerank_points(package, factors)
        score += release_age_points(package, factors)
        score += github_points(package, factors)

        package.risk_score = [score, 100].min
        package.risk_factors = factors
      end

      private

      def sourcerank_points(package, factors)
        return 0 unless package.sourcerank

        rank = package.sourcerank.to_i
        if rank < 10
          factors << "low Libraries.io SourceRank #{rank}"
          12
        elsif rank < 15
          factors << "moderate Libraries.io SourceRank #{rank}"
          6
        else
          0
        end
      end

      def release_age_points(package, factors)
        latest = parse_time(package.latest_release_published_at)
        current = parse_time(package.current_release_published_at)
        points = 0

        if latest
          days = (DateTime.now - latest).to_i
          if days > 730
            factors << "latest release is #{days} days old"
            points += 12
          elsif days > 365
            factors << "latest release is #{days} days old"
            points += 6
          end
        end

        if latest && current
          lag = (latest - current).to_i
          if lag > 365
            factors << "current version trails latest by #{lag} days"
            points += 10
          elsif lag > 180
            factors << "current version trails latest by #{lag} days"
            points += 5
          end
        end

        points
      end

      def github_points(package, factors)
        github = package.github || {}
        points = 0

        if github['issues'].to_i > 20
          points += 5
          factors << "#{github['issues']} open GitHub issues"
        end

        last_commit = parse_time(github['last_commit'])
        if last_commit
          days = (DateTime.now - last_commit).to_i
          if days > 365
            points += 12
            factors << "last GitHub commit is #{days} days old"
          elsif days > 180
            points += 6
            factors << "last GitHub commit is #{days} days old"
          end
        end

        points
      end

      def parse_time(value)
        return value if value.is_a?(DateTime)
        return nil unless value

        DateTime.parse(value.to_s)
      rescue ArgumentError
        nil
      end
    end
  end
end
