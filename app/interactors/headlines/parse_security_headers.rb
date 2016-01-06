module Headlines
  class ParseSecurityHeaders
    include Interactor

    def call
      unless response_code == 200
        context.status = response_code
        context.fail!(message: I18n.t("errors.general"))
      end

      context.ssl_enabled = URI(easy.last_effective_url).scheme == "https"
      context.headers = parse_headers.push(parse_csp)
    end

    private

    def response_code
      @response_code ||= easy.perform && easy.response_code
    rescue StandardError => exception
      context.errors = exception.inspect
      error_i18n = exception.class.to_s.gsub("::", ".").downcase
      context.fail!(message: I18n.t("errors.#{error_i18n}", default: I18n.t("errors.general")))
    end

    def parse_csp
      Headlines::SecurityHeaders::ContentSecurityPolicy.new(sanitized_headers, easy.body_str, context.url)
    end

    def parse_headers
      security_headers.map { |(header, value)| header_class(header).new(header, value) }
    end

    def security_headers
      empty_headers_hash.merge!(formatted_headers.slice(*headers_to_analyze))
    end

    def empty_headers_hash
      Hash[headers_to_analyze.zip(Array.new(headers_to_analyze.size, ""))]
    end

    def formatted_headers
      return sanitized_headers unless sanitized_headers["public-key-pins-report-only"]

      sanitized_headers.merge!("public-key-pins" => "#{sanitized_headers['public-key-pins-report-only']};report-only")
    end

    def sanitized_headers
      @sanitized_headers ||= Hash[
        response_headers.map { |k, v| [k, v.is_a?(String) ? v.force_encoding("iso8859-1").encode("utf-8") : v] }
      ]
    end

    def response_headers
      easy.header_str.split(/[\r\n]+/)
    end

    def headers_to_analyze
      SECURITY_HEADERS + OTHER_HEADERS
    end

    def header_class(header)
      "Headlines::SecurityHeaders::#{header.titleize.gsub(' ', '')}".constantize
    end

    def easy
      @easy ||= Curl::Easy.new("http://#{context.url}") do |c|
        c.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        c.headers["Accept-Encoding"] = "none"
        c.headers["Accept-Language"] = "en-US,en;q=0.5"
        c.headers["User-Agent"] = "Mozilla/5.0 AppleWebKit/537.36 Chrome/46.0.2490.71 Safari/537.36 Firefox/41.0"
        c.follow_location = true
        c.max_redirects = 10
        c.timeout = 30
        c.connect_timeout = 10
      end
    end
  end
end
