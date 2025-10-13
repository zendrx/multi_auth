require "../../multi_auth"
require "oauth2"
require "random/secure"
require "openssl"
require "base64"

class MultiAuth::Provider::XTwitter < MultiAuth::Provider
  # Store PKCE verifier per instance
  getter code_verifier : String

  def initialize(redirect_uri : String, key : String, secret : String)
    super(redirect_uri, key, secret)
    @code_verifier = generate_code_verifier
  end

  def authorize_uri(scope = nil, state = nil)
    scope ||= "tweet.read users.read offline.access"

    # Generate PKCE challenge from verifier
    code_challenge = generate_code_challenge(@code_verifier)

    client = OAuth2::Client.new(
      "x.com",
      key,
      secret,
      authorize_uri: "/i/oauth2/authorize",
      redirect_uri: redirect_uri
    )

    # Build authorization URI with PKCE parameters
    client.get_authorize_uri(scope, state) do |form|
      form.add("code_challenge", code_challenge)
      form.add("code_challenge_method", "S256")
    end
  end

  def user(params : Hash(String, String))
    x_user = fetch_x_user(params["code"])

    user = User.new(
      "x_twitter",
      x_user.id,
      x_user.name,
      x_user.raw_json.as(String),
      x_user.access_token.not_nil!
    )

    user.nickname = x_user.username
    user.description = x_user.description
    user.image = x_user.profile_image_url

    user
  end

  private class XUser
    include JSON::Serializable

    @[JSON::Field(ignore: true)]
    property raw_json : String?

    @[JSON::Field(ignore: true)]
    property access_token : OAuth2::AccessToken::Bearer?

    property id : String
    property name : String
    property username : String
    property description : String?
    property profile_image_url : String?
  end

  private def fetch_x_user(code)
    # Manually exchange authorization code for access token with PKCE
    token_client = HTTP::Client.new("api.x.com", tls: true)

    params = URI::Params.build do |form|
      form.add("code", code)
      form.add("grant_type", "authorization_code")
      form.add("client_id", key)
      form.add("redirect_uri", redirect_uri)
      form.add("code_verifier", @code_verifier)
    end

    headers = HTTP::Headers{
      "Content-Type" => "application/x-www-form-urlencoded",
    }

    response = token_client.post("/2/oauth2/token", headers: headers, body: params)
    token_data = OAuth2::AccessToken::Bearer.from_json(response.body)

    # Fetch user info from X API v2
    api = HTTP::Client.new("api.x.com", tls: true)
    api.before_request do |request|
      request.headers["Authorization"] = "Bearer #{token_data.access_token}"
    end

    # X API v2 endpoint for authenticated user
    response = api.get("/2/users/me?user.fields=description,profile_image_url")
    user_data = JSON.parse(response.body)

    # Extract user data from X API v2 response format
    data = user_data["data"]
    raw_json = data.to_json

    x_user = XUser.from_json(raw_json)
    x_user.access_token = token_data
    x_user.raw_json = raw_json
    x_user
  end

  # Generate a cryptographically secure random code verifier
  private def generate_code_verifier : String
    bytes = Random::Secure.random_bytes(32)
    Base64.urlsafe_encode(bytes, padding: false)
  end

  # Generate S256 code challenge from verifier
  private def generate_code_challenge(verifier : String) : String
    digest = OpenSSL::Digest.new("SHA256")
    digest.update(verifier)
    Base64.urlsafe_encode(digest.final, padding: false)
  end
end

MultiAuth::Providers.register("x_twitter", MultiAuth::Provider::XTwitter)
MultiAuth::Providers.register("x", MultiAuth::Provider::XTwitter)
