require "faraday"
require "typhoeus"
require "typhoeus/adapters/faraday"

module Headlines
  module ScanDomains
    class Runner
      DEFAULT_BATCH_SIZE = 500

      def initialize(total_count, progressbar)
        @total_count = total_count
        @progressbar = progressbar
      end

      def call
        Headlines::Domain.find_in_batches(batch_size: batch_size) do |domains|
          responses = []

          begin
            connection.in_parallel do
              domains.each do |domain|
                responses << connection.get("http://#{domain.name}")

                progressbar.increment
              end
            end
          rescue StandardError => exception
            failure_logger.info("  Unhandled exception: #{exception}")
          end

          responses.each do |response|
            log_scan_result(0, response)
          end

          break if progressbar.progress >= total_count
        end
      end

      private

      attr_reader :total_count, :progressbar

      def batch_size
        [DEFAULT_BATCH_SIZE, total_count].min
      end

      def scan_domain(domain)
        log_scan_result(domain.id, result)
      end

       def connection
         @connection ||= Faraday.new(headers: header_options, request: request_options) do |builder|
            builder.request :url_encoded
            builder.adapter :typhoeus
         end
      end

      def header_options
        {
          accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
          accept_encoding: "none",
          accept_language: "en-US,en;q=0.5",
          user_agent: "Mozilla/5.0 AppleWebKit/537.36 Chrome/46.0.2490.71 Safari/537.36 Firefox/41.0"
        }
      end

      def request_options
        {
          timeout: 30,
          open_timeout: 10
        }
      end

      # def scan_domain(domain)
      #   result = Headlines::AnalyzeDomainHeaders.call(url: domain.name)
      #   if result.success?
      #     domain.build_last_scan(scan_params(result).merge(domain_id: domain.id, ssl_enabled: result.ssl_enabled))
      #     domain.save!
      #   end

      #   log_scan_result(domain.id, result)
      # end

      def scan_params(result)
        result[:params].slice(:headers, :results, :score, :http_score, :csp_score)
      end

      def log_scan_result(index, result)
        domain_name = result.env[:url]
        scan_result = result.success? ? "success" : "failure"
        logger.info("Domain #{domain_name} scan result: #{scan_result}")
        return if result.success?

        failure_logger.info("#{domain_name}")
        failure_logger.info("  Status: #{result.status}") if result.status.present?
        # failure_logger.info("  Errors: #{result.errors}") if result.errors.present?
      end

      def logger
        @logger ||= Logger.new(Rails.root.join("log/scan_domains.log"))
      end

      def failure_logger
        @failure_logger ||= Logger.new(Rails.root.join("log/scan_domains_failure.log"))
      end
    end
  end
end
