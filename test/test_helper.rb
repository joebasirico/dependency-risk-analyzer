$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))

require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require 'json'
require 'dependency_risk'

FIXTURE_DIR = File.expand_path('fixtures', __dir__)

def fixture_path(name)
  File.join(FIXTURE_DIR, name)
end

def capture_stdout
  original = $stdout
  reader, writer = IO.pipe
  $stdout = writer
  yield
  writer.close
  reader.read
ensure
  $stdout = original
  reader.close if reader && !reader.closed?
end
