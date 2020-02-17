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

  SPOTIFY_ACCOUNTS_ENDPOINT = URI.parse("https://accounts.spotify.com")
SPOTIFY_API_ENDPOINT = URI.parse("https://api.spotify.com")
CLIENT_ID = "9a41d6d229754090b8cd983dacfc89e7"
CLIENT_SECRET = "a20fcd1ebc7e481c8c9ee0469d5385b3"
ENCRYPTION_SECRET = "|NwDQ-R1J,:1ct^@m+[s&C(k}2g]g+T|AuPXz07AT7jB oFjk|tCY+|/|Y:u[Er8"
CLIENT_CALLBACK_URL = "syncs-login://callback"
AUTH_HEADER = "Basic " + Base64.strict_encode64(CLIENT_ID + ":" + CLIENT_SECRET)
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
      self.client_callback_url = "syncs-login://callback"
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

    # def playlists(limit:, offset: )
    #   options = default_options.deep_merge(query: {
    #     limit: limit,
    #     offset: offset
    #   })
    #   self.class.post("/v1/me/playlists", options)
    # end

    def recoomend()
      options = default_options.deep_merge(query: {
      })

      self.class.post("/v1/recommendations", options)
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

      # if response[:refresh_token].present?
      #   response[:refresh_token] = encrypt_refresh_token(response[:refresh_token])
      # end

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

    def recommended
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

    post '/refresh' do

      # Request a new access token using the POST:ed refresh token
  
      http = Net::HTTP.new(SPOTIFY_ACCOUNTS_ENDPOINT.host, SPOTIFY_ACCOUNTS_ENDPOINT.port)
      http.use_ssl = true
  
      request = Net::HTTP::Post.new("/api/token")
  
      request.add_field("Authorization", AUTH_HEADER)
      # encrypted_token = params[:refresh_token]
      # refresh_token = encrypted_token.decrypt(:symmetric, :password => ENCRYPTION_SECRET)
      refresh_token = params[:refresh_token]
      request.form_data = {
          "grant_type" => "refresh_token",
          "refresh_token" => refresh_token
      }
  
      response = http.request(request)
  
      status response.code.to_i
      return response.body
  
  end

  

get '/v1/me/playlists' do

  # Request a new access token using the POST:ed refresh token

  http = Net::HTTP.new(SPOTIFY_API_ENDPOINT.host, SPOTIFY_API_ENDPOINT.port)
  http.use_ssl = true

  request = Net::HTTP::Get.new("/v1/me/playlists")
  auth = "Bearer " + params[:auth]
  request.add_field("Authorization", auth)

  # encrypted_token = params[:refresh_token]
  # refresh_token = encrypted_token.decrypt(:symmetric, :password => ENCRYPTION_SECRET)
  # refresh_token = params[:refresh_token]
  request.form_data = {
      # "grant_type" => "refresh_token",
      # "refresh_token" => refresh_token
  }

  response = http.request(request)

  status response.code.to_i
  return response.body

end


get '/v1/me' do

  # Request a new access token using the POST:ed refresh token

  http = Net::HTTP.new(SPOTIFY_API_ENDPOINT.host, SPOTIFY_API_ENDPOINT.port)
  http.use_ssl = true

  request = Net::HTTP::Get.new("/v1/me")
  auth = "Bearer " + params[:auth]
  request.add_field("Authorization", auth)

  # encrypted_token = params[:refresh_token]
  # refresh_token = encrypted_token.decrypt(:symmetric, :password => ENCRYPTION_SECRET)
  # refresh_token = params[:refresh_token]
  request.form_data = {
      # "grant_type" => "refresh_token",
      # "refresh_token" => refresh_token
  }

  response = http.request(request)

  status response.code.to_i
  return response.body

end

put '/v1/me/player/play' do

  # Request a new access token using the POST:ed refresh token

  http = Net::HTTP.new(SPOTIFY_API_ENDPOINT.host, SPOTIFY_API_ENDPOINT.port)
  http.use_ssl = true

  request = Net::HTTP::Put.new("/v1/me/player/play")
  auth = "Bearer " + params[:auth]
  request.add_field("Authorization", auth)
  request.add_field("Accept", "application/json")
  request.add_field("Content-Type", "application/json")
  # context_uri = params[:context_uri]
  # request.add_field("context_uri", "spotify:album:1Je1IMUlBXcx1Fz0WE7oPT")
  # encrypted_token = params[:refresh_token]
  # refresh_token = encrypted_token.decrypt(:symmetric, :password => ENCRYPTION_SECRET)
  # refresh_token = params[:refresh_token]
  # request.set_form_data({"context_uri" => "spotify:track:1301WleyT98MSxVHPZCA6M"})
  request.body = '{"context_uri":"spotify:album:1Je1IMUlBXcx1Fz0WE7oPT"}'
  request.form_data = {
      # "grant_type" => "refresh_token",
      # "refresh_token" => refresh_token
      # "context_uri" => "spotify:album:1Je1IMUlBXcx1Fz0WE7oPT"
  }

  response = http.request(request)

  status response.code.to_i
  return response.body

end

get '/v1/search' do

  # Request a new access token using the POST:ed refresh token

  http = Net::HTTP.new(SPOTIFY_API_ENDPOINT.host, SPOTIFY_API_ENDPOINT.port)
  http.use_ssl = true

  request = Net::HTTP::Get.new("/v1/search?q=dias%20de%20luta&type=artist%2Ctrack")
  auth = "Bearer " + params[:auth]
  request.add_field("Authorization", auth)
  # request.add_field("q", params[:q])
  # request.add_field("type", params[:type])
  # encrypted_token = params[:refresh_token]
  # refresh_token = encrypted_token.decrypt(:symmetric, :password => ENCRYPTION_SECRET)
  # refresh_token = params[:refresh_token]
  request.form_data = {
    # "q" => params[:q],
    # "type" => params[:type]
      # "grant_type" => "refresh_token",
      # "refresh_token" => refresh_token
  }

  response = http.request(request)

  status response.code.to_i
  return response.body

end

get '/v1/me/player/recently-played' do

  # Request a new access token using the POST:ed refresh token

  http = Net::HTTP.new(SPOTIFY_API_ENDPOINT.host, SPOTIFY_API_ENDPOINT.port)
  http.use_ssl = true

  request = Net::HTTP::Get.new("/v1/me/player/recently-played")
  auth = "Bearer " + params[:auth]
  request.add_field("Authorization", auth)

  # encrypted_token = params[:refresh_token]
  # refresh_token = encrypted_token.decrypt(:symmetric, :password => ENCRYPTION_SECRET)
  # refresh_token = params[:refresh_token]
  request.form_data = {
      # "grant_type" => "refresh_token",
      # "refresh_token" => refresh_token
  }

  response = http.request(request)

  status response.code.to_i
  return response.body

end

get '/v1/me/top/tracks' do

  # Request a new access token using the POST:ed refresh token

  http = Net::HTTP.new(SPOTIFY_API_ENDPOINT.host, SPOTIFY_API_ENDPOINT.port)
  http.use_ssl = true

  request = Net::HTTP::Get.new("/v1/me/top/tracks")
  auth = "Bearer " + params[:auth]
  request.add_field("Authorization", auth)

  # encrypted_token = params[:refresh_token]
  # refresh_token = encrypted_token.decrypt(:symmetric, :password => ENCRYPTION_SECRET)
  # refresh_token = params[:refresh_token]
  request.form_data = {
      # "grant_type" => "refresh_token",
      # "refresh_token" => refresh_token
  }

  response = http.request(request)

  status response.code.to_i
  return response.body

end

    get "/v1/recommendations" do
      begin
        refresh_params = DecryptParameters.new(params).run
        http = HTTP.new.recommendations()
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
