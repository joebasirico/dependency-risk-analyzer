module DependencyRisk
  module Policy
    class LicensePolicy
      def initialize(directory:)
        @directory = directory
        @acceptable = read_policy('acceptable.txt')
        @attribution = read_policy('attribution.txt')
        @dynamic_link = read_policy('dynamic_link.txt')
        @reject = read_policy('reject.txt')
      end

      def evaluate(package)
        licenses = Array(package.licenses)
        result = if licenses.empty?
                   { 'status' => 'unknown', 'findings' => ['No license found'] }
                 else
                   evaluate_licenses(licenses)
                 end
        package.license_result = result
        result
      end

      private

      def evaluate_licenses(licenses)
        findings = []
        statuses = licenses.map do |license|
          if include_license?(@reject, license)
            findings << "#{license} is rejected"
            'rejected'
          elsif include_license?(@dynamic_link, license)
            findings << "#{license} requires dynamic linking review"
            'caution'
          elsif include_license?(@attribution, license)
            findings << "#{license} requires attribution"
            'caution'
          elsif include_license?(@acceptable, license)
            findings << "#{license} is acceptable"
            'accepted'
          else
            findings << "#{license} is unknown"
            'unknown'
          end
        end

        status = if statuses.include?('rejected')
                   'rejected'
                 elsif statuses.include?('caution')
                   'caution'
                 elsif statuses.include?('unknown')
                   'unknown'
                 else
                   'accepted'
                 end
        { 'status' => status, 'findings' => findings }
      end

      def include_license?(list, license)
        normalized = normalize(license)
        list.any? { |item| normalize(item) == normalized }
      end

      def normalize(value)
        value.to_s.strip.downcase
      end

      def read_policy(filename)
        path = File.join(@directory, filename)
        return [] unless File.file?(path)

        File.readlines(path).map(&:strip).reject(&:empty?).reject { |line| line.start_with?('#') }
      end
    end
  end
end
