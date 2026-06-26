require 'json'
require 'open3'

module DependencyRisk
  module Sbom
    class Syft
      def self.packages_from_json(data)
        Array(data.fetch('artifacts', [])).map do |artifact|
          Models::Package.from_syft_artifact(artifact)
        end.uniq(&:key)
      end

      def initialize(directory: nil, sbom_path: nil)
        @directory = directory
        @sbom_path = sbom_path
      end

      def packages
        self.class.packages_from_json(load_json)
      end

      def load_json
        if @sbom_path
          JSON.parse(File.read(expanded_file(@sbom_path)))
        else
          run_syft
        end
      end

      private

      def run_syft
        raise 'Directory is required when no SBOM path is provided' unless @directory

        directory = File.expand_path(@directory)
        raise "Directory #{directory} does not exist" unless Dir.exist?(directory)
        raise 'syft executable not found' unless executable?('syft')

        output, status = Open3.capture2e('syft', '-o', 'syft-json', directory)
        raise "Syft execution failed: #{output}" unless status.success?

        JSON.parse(output)
      end

      def expanded_file(path)
        expanded = File.expand_path(path)
        raise "File #{expanded} does not exist" unless File.file?(expanded)

        expanded
      end

      def executable?(command)
        _stdout, status = Open3.capture2('which', command)
        status.success?
      end
    end
  end
end
