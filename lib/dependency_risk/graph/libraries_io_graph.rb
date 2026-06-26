module DependencyRisk
  module Graph
    class LibrariesIoGraph
      def initialize(client:)
        @client = client
      end

      def expand!(packages, max_depth:)
        return [] unless @client.available? && max_depth.to_i.positive?

        by_package_key = packages.each_with_object({}) { |pkg, memo| memo[pkg.package_key] = pkg }
        roots = packages.select(&:direct)
        roots.each { |root| expand_package(root, root.key, by_package_key, 0, max_depth.to_i, {}) }
      end

      private

      def expand_package(package, root_key, by_package_key, depth, max_depth, seen)
        return if depth >= max_depth
        return if seen[[root_key, package.key]]

        seen[[root_key, package.key]] = true

        @client.dependencies(package).each do |dependency|
          installed = by_package_key[dependency.package_key]
          next unless installed

          package.dependencies << installed.key unless package.dependencies.include?(installed.key)
          installed.introduced_by << root_key unless installed.introduced_by.include?(root_key)
          expand_package(installed, root_key, by_package_key, depth + 1, max_depth, seen)
        end
      end
    end
  end
end
