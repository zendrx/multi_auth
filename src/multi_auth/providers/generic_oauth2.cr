require "../../multi_auth"
require "oauth2"

# GenericOAuth2 provider allows dynamic OAuth2 provider configuration
# Use with the factory method for database-driven provider configuration:
#
# ```
# MultiAuth.config("my_provider_123") do |provider_name, redirect_uri|
#   config = load_from_database(provider_name) # Your DB logic
#   MultiAuth::Provider::GenericOAuth2.new(
#     provider_name: config.name,
#     redirect_uri: redirect_uri,
#     key: config.client_id,
#     secret: config.client_secret,
#     site: config.site,
#     authorize_url: config.authorize_url,
#     token_url: config.token_url,
#     authentication_scheme: config.authentication_scheme,
#     user_profile_url: config.user_profile_url,
#     scopes: config.scopes,
#     info_mappings: config.info_mappings
#   )
# end
# ```
class MultiAuth::Provider::GenericOAuth2 < MultiAuth::Provider
  getter provider_name : String
  getter site : String
  getter authorize_url : String
  getter token_url : String
  getter authentication_scheme : String
  getter user_profile_url : String
  getter scopes : String
  getter info_mappings : Hash(String, String)

  # Prevent static configuration - GenericOAuth2 must be used with factory method
  def self.new(redirect_uri : String, key : String, secret : String)
    raise "Static OAuth configuration not supported for GenericOAuth2. Use the factory method: MultiAuth.config(provider_name) { |name, uri| ... }"
  end

  def initialize(
    *,
    @provider_name : String,
    @redirect_uri : String,
    @key : String,
    @secret : String,
    @site : String,
    @authorize_url : String,
    @token_url : String,
    @authentication_scheme : String,
    @user_profile_url : String,
    @scopes : String,
    @info_mappings : Hash(String, String),
  )
  end

  def authorize_uri(scope = nil, state = nil)
    scope ||= @scopes

    # Parse site URL to get host
    uri = URI.parse(@site)
    host = uri.host || @site

    client = OAuth2::Client.new(
      host,
      @key,
      @secret,
      authorize_uri: @authorize_url,
      redirect_uri: @redirect_uri
    )

    client.get_authorize_uri(scope, state)
  end

  def user(params : Hash(String, String))
    generic_user = fetch_user(params["code"])

    # Map the user data using info_mappings
    user = User.new(
      @provider_name,
      get_mapped_value(generic_user, "uid") || "",
      get_mapped_value(generic_user, "name"),
      generic_user.raw_json.as(String),
      generic_user.access_token.not_nil!
    )

    # Map optional fields
    user.email = get_mapped_value(generic_user, "email")
    user.nickname = get_mapped_value(generic_user, "nickname")
    user.first_name = get_mapped_value(generic_user, "first_name")
    user.last_name = get_mapped_value(generic_user, "last_name")
    user.location = get_mapped_value(generic_user, "location")
    user.description = get_mapped_value(generic_user, "description")
    user.image = get_mapped_value(generic_user, "image")
    user.phone = get_mapped_value(generic_user, "phone")

    # Handle URLs mapping - can map multiple URL fields
    urls = {} of String => String
    @info_mappings.each do |key, json_key|
      if key.starts_with?("url_")
        url_name = key[4..]
        if parsed_json = generic_user.parsed_json
          if value = get_value_from_json(parsed_json, json_key)
            urls[url_name] = value
          end
        end
      end
    end
    user.urls = urls unless urls.empty?

    user
  end

  private class GenericUser
    property raw_json : String?
    property access_token : OAuth2::AccessToken?
    property parsed_json : JSON::Any?

    def initialize(@raw_json, @access_token, @parsed_json)
    end
  end

  private def fetch_user(code)
    # Parse site URL
    uri = URI.parse(@site)
    host = uri.host || @site

    # Determine auth scheme
    auth_scheme : OAuth2::AuthScheme = case @authentication_scheme.downcase
    when "basic", "http_basic"
      OAuth2::AuthScheme::HTTPBasic
    when "request_body", "body"
      OAuth2::AuthScheme::RequestBody
    else
      OAuth2::AuthScheme::RequestBody
    end

    client = OAuth2::Client.new(
      host,
      @key,
      @secret,
      token_uri: @token_url,
      redirect_uri: @redirect_uri,
      auth_scheme: auth_scheme
    )

    access_token = client.get_access_token_using_authorization_code(code)

    # Fetch user profile
    profile_uri = URI.parse(@user_profile_url)
    profile_host = profile_uri.host || host

    api = HTTP::Client.new(profile_host, tls: profile_uri.scheme == "https")
    access_token.authenticate(api)

    # Get the path with query params
    profile_path = profile_uri.path
    profile_path += "?#{profile_uri.query}" if profile_uri.query

    raw_json = api.get(profile_path).body
    parsed_json = JSON.parse(raw_json)

    GenericUser.new(raw_json, access_token, parsed_json)
  end

  # Get mapped value from the parsed JSON using the configured mapping
  private def get_mapped_value(generic_user : GenericUser, field : String) : String?
    return nil unless json_key = @info_mappings[field]?
    return nil unless parsed_json = generic_user.parsed_json

    get_value_from_json(parsed_json, json_key)
  end

  # Extract value from JSON using dot notation for nested fields
  # Examples: "user.id", "profile.email", "data.attributes.name"
  private def get_value_from_json(json : JSON::Any, path : String) : String?
    parts = path.split('.')
    current = json

    parts.each do |part|
      # Handle array access like "data[0]" or just object access "data"
      if part.includes?('[')
        # Extract the key and index
        key, index_str = part.split('[', 2)
        index = index_str.rstrip(']').to_i

        current = current[key]?
        return nil unless current

        current = current[index]?
        return nil unless current
      else
        current = current[part]?
        return nil unless current
      end
    end

    # Handle different JSON types
    current.raw.to_s
  rescue
    nil
  end
end
