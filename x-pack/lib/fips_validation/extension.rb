
require "logstash/environment"

require "logstash/plugins/registry"

module LogStash
  module FipsValidation
    class Extension < LogStash::UniversalPlugin

      LogStash::PLUGIN_REGISTRY.add(:universal, "fips_validation", self)

      include LogStash::Util::Loggable

      def register_hooks(hooks)
        require 'logstash/runner'
        hooks.register_hooks(LogStash::Runner, self)
      end

      def before_bootstrap_checks(runner)
        return unless ENV['ENFORCE_FIPS_140_3']

        issues = []

        # naive security provider check: specific three in specific order
        observed_security_providers = ::Java::java.security.Security.getProviders.map(&:name)
        expected_security_providers = %w(BCFIPS BCJSSE SUN)
        if observed_security_providers != expected_security_providers
          issues << "Java security providers are misconfigured (expected `#{expected_security_providers}`, observed `#{observed_security_providers}`)"
        end

        # naive secure-random provider check:
        observed_random_provider = ::Java::java.security.SecureRandom.new.getProvider.getName
        expected_random_provider = "BCFIPS"
        unless observed_random_provider == expected_random_provider
          issues << "Java SecureRandom provider is misconfigured (expected `#{expected_random_provider}`; observed `#{observed_random_provider}`)"
        end

        # ensure Bouncycastle is configured and ready
        begin
          unless Java::org.bouncycastle.crypto.CryptoServicesRegistrar.isInApprovedOnlyMode
            issues << "Bouncycastle Crypto is not in 'approved-only' mode"
          end

          unless ::Java::org.bouncycastle.crypto.fips.FipsStatus.isReady
            issues << "Bouncycastle Crypto is not fips-ready"
          end
        rescue => ex
          issues << "Bouncycastle Crypto unavailable: (#{ex.class}) #{ex.message}"
        end

        # ensure non-compliant jruby openssl provider isn't registered
        if org.jruby.ext.openssl.SecurityHelper.isProviderRegistered
          issues << "non-compliant Jruby OpenSSL security helper is registered"
        end

        if issues.any?
          fail LogStash::ConfigurationError, "FIPS compliance issues: #{issues}"
        end
      end
    end
  end
end