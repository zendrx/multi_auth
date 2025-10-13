require "../../multi_auth"
require "oauth2"

class MultiAuth::Provider::Discord < MultiAuth::Provider
  def authorize_uri(scope = nil, state = nil)
    defaults = [
      "identify",
    ]

    scope ||= defaults.join(" ")

    client = OAuth2::Client.new(
      "discord.com",
      key,
      secret,
      authorize_uri: "/oauth2/authorize",
      redirect_uri: redirect_uri
    )

    client.get_authorize_uri(scope, state)
  end

  def user(params : Hash(String, String))
    client = OAuth2::Client.new(
      "discord.com",
      key,
      secret,
      token_uri: "/api/oauth2/token",
      redirect_uri: redirect_uri,
      auth_scheme: :request_body
    )

    access_token = client.get_access_token_using_authorization_code(params["code"])

    api = HTTP::Client.new("discord.com", tls: true)
    access_token.authenticate(api)

    raw_json = api.get("/api/oauth2/@me").body

    build_user(raw_json, access_token)
  end

  private def json
    @json.as(JSON::Any)
  end

  private def build_user(raw_json, access_token)
    @json = JSON.parse(raw_json)

    user = User.new(
      "discord",
      json["user"].as_h["id"].as_s,
      json["user"].as_h["username"].as_s,
      raw_json,
      access_token
    )

    if avatar = json["user"].as_h["avatar"]?
      user.image = "https://cdn.discordapp.com/avatars/#{json["user"].as_h["id"]}/#{avatar}"
    end

    user
  end
end

MultiAuth::Providers.register("discord", MultiAuth::Provider::Discord)
