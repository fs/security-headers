module Headlines
  class ParseSecurityHeaders
    include Interactor

    def call
      unless response.success?
        context.status = response.status
        context.fail!
      end

      context.headers = parse_headers.push(parse_csp)
    end

    private

    def response
      @response ||= get_or_post
    rescue Faraday::ClientError, URI::InvalidURIError, Errno::ETIMEDOUT
      @response = head_request
    end

    def get_or_post
      response = connection.get("/")
      response.success? ? response : connection.post("/")
    end

    def head_request
      @head_request = connection.head("/")
    rescue Faraday::ClientError, URI::InvalidURIError, Errno::ETIMEDOUT => exception
      context.errors = exception.inspect
      context.fail!(message: I18n.t("connection.failed", url: context.url))
    end

    def parse_csp
      Headlines::SecurityHeaders::ContentSecurityPolicy.new(response.headers, response.body, context.url)
    end

    def parse_headers
      security_headers.map { |(header, value)| header_class(header).new(header, value) }
    end

    def security_headers
      empty_headers_hash.merge(formatted_headers.slice(*SECURITY_HEADERS))
    end

    def empty_headers_hash
      Hash[SECURITY_HEADERS.zip(Array.new(SECURITY_HEADERS.size, ""))]
    end

    def formatted_headers
      return response.headers unless response.headers["public-key-pins-report-only"]

      response.headers.merge("public-key-pins" => "#{response.headers['public-key-pins-report-only']};report-only")
    end

    def header_class(header)
      "Headlines::SecurityHeaders::#{header.titleize.gsub(' ', '')}".constantize
    end

    def connection
      Faraday.new(url: "http://#{context.url}", headers: request_headers, ssl: { verify: false }) do |builder|
        builder.request :url_encoded
        builder.response :logger
        builder.use FaradayMiddleware::FollowRedirects, limit: 10, standards_compliant: true
        builder.adapter Faraday.default_adapter
      end
    end

    def request_headers
      {
        accept_encoding: "none",
        user_agent: "Mozilla/5.0 AppleWebKit/537.36 Chrome/46.0.2490.71 Safari/537.36 Firefox/41.0"
      }
    end
  end
end
