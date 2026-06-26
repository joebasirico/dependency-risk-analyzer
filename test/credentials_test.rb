require_relative 'test_helper'

class CredentialsTest < Minitest::Test
  Status = Struct.new(:ok) do
    def success?
      ok
    end
  end

  def test_fetch_prefers_environment_variable
    with_env('LIBRARIES_IO_API_KEY' => 'from-env') do
      with_singleton_method(DependencyRisk::Credentials, :executable?, proc { |_command| raise 'op should not be checked' }) do
        assert_equal 'from-env', DependencyRisk::Credentials.fetch('LIBRARIES_IO_API_KEY', 'op://Personal/token')
      end
    end
  end

  def test_fetch_tries_1password_paths_until_one_succeeds
    calls = []
    responses = [
      ['', 'missing vault', Status.new(false)],
      ["from-op\n", '', Status.new(true)]
    ]

    with_env('LIBRARIES_IO_API_KEY' => nil) do
      with_singleton_method(DependencyRisk::Credentials, :executable?, proc { |_command| true }) do
        with_singleton_method(Open3, :capture3, proc { |*args|
          calls << args
          responses.shift
        }) do
          value = DependencyRisk::Credentials.fetch(
            'LIBRARIES_IO_API_KEY',
            [
              'op://Employee/Libraries.ioAPIToken/credential',
              'op://Personal/Libraries.ioAPIToken/credential'
            ]
          )

          assert_equal 'from-op', value
        end
      end
    end

    assert_equal [
      ['op', 'read', 'op://Employee/Libraries.ioAPIToken/credential'],
      ['op', 'read', 'op://Personal/Libraries.ioAPIToken/credential']
    ], calls
  end

  def test_fetch_allows_environment_configured_1password_path
    calls = []

    with_env(
      'LIBRARIES_IO_API_KEY' => nil,
      'LIBRARIES_IO_API_KEY_OP_PATH' => 'op://Personal/custom/credential'
    ) do
      with_singleton_method(DependencyRisk::Credentials, :executable?, proc { |_command| true }) do
        with_singleton_method(Open3, :capture3, proc { |*args|
          calls << args
          ['custom-secret', '', Status.new(true)]
        }) do
          value = DependencyRisk::Credentials.fetch('LIBRARIES_IO_API_KEY', 'op://Private/default/credential')

          assert_equal 'custom-secret', value
        end
      end
    end

    assert_equal [['op', 'read', 'op://Personal/custom/credential']], calls
  end

  def test_github_token_prefers_environment_variable
    with_env('GITHUB_TOKEN' => 'from-env') do
      with_singleton_method(DependencyRisk::Credentials, :executable?, proc { |_command| raise 'gh should not be checked' }) do
        assert_equal 'from-env', DependencyRisk::Credentials.github_token
      end
    end
  end

  def test_github_token_uses_gh_auth_token
    calls = []

    with_env('GITHUB_TOKEN' => nil) do
      with_singleton_method(DependencyRisk::Credentials, :executable?, proc { |_command| true }) do
        with_singleton_method(Open3, :capture3, proc { |*args|
          calls << args
          ["from-gh\n", '', Status.new(true)]
        }) do
          assert_equal 'from-gh', DependencyRisk::Credentials.github_token
        end
      end
    end

    assert_equal [['gh', 'auth', 'token']], calls
  end

  private

  def with_env(values)
    previous = {}
    values.each do |key, value|
      previous[key] = ENV.key?(key) ? ENV[key] : :__missing__
      value.nil? ? ENV.delete(key) : ENV[key] = value
    end

    yield
  ensure
    previous.each do |key, value|
      value == :__missing__ ? ENV.delete(key) : ENV[key] = value
    end
  end

  def with_singleton_method(object, method_name, implementation)
    singleton = class << object; self; end
    original = singleton.instance_method(method_name)
    singleton.define_method(method_name, implementation)
    yield
  ensure
    singleton.define_method(method_name, original)
  end
end
