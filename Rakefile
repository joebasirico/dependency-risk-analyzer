task :test do
  $LOAD_PATH.unshift(File.expand_path('test', __dir__))
  Dir[File.join(__dir__, 'test/*_test.rb')].sort.each do |file|
    require file
  end
end

task default: :test
