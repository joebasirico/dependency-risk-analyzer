require 'rbconfig'

module DependencyRisk
  module Boot
    module_function

    def app_root
      File.expand_path('../..', __dir__)
    end

    def bundle_root
      ruby_key = [
        RbConfig::CONFIG.fetch('ruby_version'),
        RbConfig::CONFIG.fetch('arch')
      ].join('-')
      File.join(app_root, '.bundle', 'gems', ruby_key)
    end

    def gem_home
      File.join(bundle_root, 'ruby', RbConfig::CONFIG.fetch('ruby_version'))
    end

    def isolate_gems!
      ENV['GEM_HOME'] = gem_home
      ENV['GEM_PATH'] = gem_home
      ENV['BUNDLE_PATH'] = bundle_root
      ENV['BUNDLE_APP_CONFIG'] = File.join(app_root, '.bundle')
      Gem.clear_paths if defined?(Gem)
    end
  end
end
