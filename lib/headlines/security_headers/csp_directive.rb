module Headlines
  module SecurityHeaders
    class CspDirective
      SRC_DIRECTIVES = %w(child-src
                          connect-src
                          default-src
                          font-src
                          frame-src
                          img-src
                          media-src
                          object-src
                          script-src
                          style-src)

      attr_accessor :in_meta
      attr_writer :sources

      def initialize(directive, in_meta = false)
        @directive = directive
        @in_meta = in_meta
      end

      def name
        @name ||= @directive.split(" ")[0]
      end

      def value
        @value ||= sources.join(" ")
      end

      def sources
        @sources ||= @directive.split(" ")[1..-1]
      end

      def sources_hosts
        sources.map { |source| source.gsub(%r{(https?://)?(www.)?}, "") } - ["'none'", "'self'", "'*'"]
      end

      def invalid?
        SRC_DIRECTIVES.include?(name) && (sources.include?("'*'") || sources.include?("'none'")) && sources.size > 1
      end

      def valid?
        !invalid?
      end

      def http_domain_name?
        sources.select { |s| s.include?(".") && !s.start_with?("https://") }.any?
      end

      def https_value?
        sources.include?("https:")
      end

      def allows_unsecured_http?
        sources.include?("http:")
      end

      def allows_unsecured_http2?
        http_domain_name? && !https_value?
      end

      def restrictive_default_settings?
        name == "default-src" && value =~ /^('none'|'self')$/
      end

      def permissive_default_settings?
        name == "default-src" && value =~ /^'\*'$/
      end

      def scripts_from_any_host?
        name == "script-src" && value =~ /^'\*'$/
      end

      def styles_from_any_host?
        name == "style-src" && value =~ /^'\*'$/
      end

      def restrict_javascript?
        name == "script-src" && value =~ /^'self'$/
      end

      def restrict_stylesheets?
        name == "style-src" && value =~ /^'self'$/
      end

      def javascript_nonce?
        name == "script-src" && value =~ /^'nonce-/
      end

      def stylesheets_nonce?
        name == "style-src" && value =~ /^'nonce-/
      end

      def unsafe_eval_without_nonce?
        in_list?(name) && sources.include?("'unsafe-eval'") && !(sources.include?("'nonce'"))
      end

      def unsafe_inline_without_nonce?
        in_list?(name) && sources.include?("'unsafe-inline'") && !(sources.include?("'nonce'"))
      end

      def allow_potentially_unsecure_host?
        in_list?(name) && (sources_hosts - SiteSetting.whitelisted_domains.split("|")).any?
      end

      def in_list?(name)
        %w(default-src script-src style-src).include?(name)
      end

      def frame_ancestors_in_meta?
        name == "frame-ancestors" && in_meta
      end

      def sandbox_in_meta?
        name == "sandbox" && in_meta
      end
    end
  end
end
