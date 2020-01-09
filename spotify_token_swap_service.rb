require "sinatra"
require "sinatra/json"
require "sinatra/reloader" if File.exists?(".env")
require "dotenv/load" if File.exists?(".env")
require "active_support/all"
require "base64"
require "encrypted_strings"
require "singleton"
require "httparty"

module SpotifyTokenSwapService

  # SpotifyTokenSwapService::ConfigHelper
  # SpotifyTokenSwapService::ConfigError
  # SpotifyTokenSwapService::Config
  #
  # This deals with configuration, loaded through .env
  #
  module ConfigHelper
    def config
      @config ||= Config.instance
    end
  end

  class ConfigError < StandardError
    def self.empty
      new("client credentials are empty")
    end
  end

  class Config < Struct.new(:client_id, :client_secret,
                            :client_callback_url, :encryption_secret)
    include Singleton

    def initialize
      self.client_id = ENV["SPOTIFY_CLIENT_ID"]
      self.client_secret = ENV["SPOTIFY_CLIENT_SECRET"]
      self.client_callback_url = ENV["SPOTIFY_CLIENT_CALLBACK_URL"]
      self.encryption_secret = ENV["ENCRYPTION_SECRET"]

      validate_client_credentials
    end

    def has_client_credentials?
      client_id.present? &&
      client_secret.present? &&
      client_callback_url.present?
    end

    def has_encryption_secret?
      encryption_secret.present?
    end

    private

    def validate_client_credentials
      raise ConfigError.empty unless has_client_credentials?
    end
  end

  # SpotifyTokenSwapService::HTTP
  #
  # Make the HTTP requests, as handled by our lovely host, HTTParty.
  #
  class HTTP
    include HTTParty,
            ConfigHelper
    base_uri "https://accounts.spotify.com"

    def token(auth_code:)
      options = default_options.deep_merge(query: {
        grant_type: "authorization_code",
        redirect_uri: config.client_callback_url,
        code: auth_code
      })

      self.class.post("/api/token", options)
    end

    def refresh_token(refresh_token:)
      options = default_options.deep_merge(query: {
        grant_type: "refresh_token",
        refresh_token: refresh_token
      })

      self.class.post("/api/token", options)
    end

    private

    def default_options
      { headers: { Authorization: authorization_basic } }
    end

    def authorization_basic
      "Basic %s" % Base64.strict_encode64("%s:%s" % [
        config.client_id,
        config.client_secret
      ])
    end
  end

  # SpotifyTokenSwapService::EncryptionMiddleware
  #
  # The code needed to apply encryption middleware for refresh tokens.
  #
  class EncryptionMiddleware < Struct.new(:httparty_instance)
    include ConfigHelper

    def run
      response = httparty_instance.parsed_response.with_indifferent_access

      if response[:refresh_token].present?
        response[:refresh_token] = encrypt_refresh_token(response[:refresh_token])
      end

      [httparty_instance.response.code.to_i, response]
    end

    private

    def encrypt_refresh_token(refresh_token)
      if config.has_encryption_secret?
        refresh_token.encrypt(:symmetric, password: ENV["ENCRYPTION_SECRET"])
      end || refresh_token
    end
  end

  # SpotifyTokenSwapService::DecryptParameters
  #
  # The code needed to apply decryption middleware for refresh tokens.
  #
  class DecryptParameters < Struct.new(:params)
    include ConfigHelper

    def initialize(init_params)
      self.params = init_params.with_indifferent_access
    end

    def refresh_token
      params[:refresh_token].to_s.gsub("\\n", "\n")
    end

    def run
      params.merge({
        refresh_token: decrypt_refresh_token(refresh_token)
      })
    end

    private

    def decrypt_refresh_token(refresh_token)
      if config.has_encryption_secret?
        refresh_token.decrypt(:symmetric, password: ENV["ENCRYPTION_SECRET"])
      end || refresh_token
    end
  end

  # SpotifyTokenSwapService::EmptyMiddleware
  #
  # Similar to EncryptionMiddleware, but it does nothing except
  # comply with our DSL for middleware - [status code, response]
  #
  class EmptyMiddleware < Struct.new(:httparty_instance)
    include ConfigHelper

    def run
      response = httparty_instance.parsed_response.with_indifferent_access
      [httparty_instance.response.code.to_i, response]
    end
  end

  # SpotifyTokenSwapService::App
  #
  # The code needed to make it go all Sinatra, beautiful.
  #
  class App < Sinatra::Base
    set :root, File.dirname(__FILE__)

    before do
      headers "Access-Control-Allow-Origin" => "*",
              "Access-Control-Allow-Methods" => %w(OPTIONS GET POST)
    end

    helpers ConfigHelper

    # POST /api/token
    # Convert an authorization code to an access token.
    #
    # @param code The authorization code sent from accounts.spotify.com
    #
    post "/api/token" do
      begin
        http = HTTP.new.token(auth_code: params[:code])
        status_code, response = EncryptionMiddleware.new(http).run

        status status_code
        json response
      rescue StandardError => e
        status 400
        json error: e
      end
    end

    # POST /api/refresh_token
    # Use a refresh token to generate a one-hour access token.
    #
    # @param refresh_token The refresh token provided from /api/token
    #
    post "/api/refresh_token" do
      begin
        refresh_params = DecryptParameters.new(params).run
        http = HTTP.new.refresh_token(refresh_token: refresh_params[:refresh_token])
        status_code, response = EmptyMiddleware.new(http).run

        status status_code
        json response
      rescue OpenSSL::Cipher::CipherError
        status 400
        json error: "invalid refresh_token"
      rescue StandardError => e
        status 400
        json error: e
      end
    end
  end
end
