require "../multi_auth"
require "./discovery/well_known"

module MultiAuth::Discovery
  # Discover OAuth2 configuration from a domain using .well-known/oauth-authorization-server
  #
  # Example:
  # ```
  # config = MultiAuth::Provider::GenericOAuth2.discover("https://gitlab.com")
  #
  # MultiAuth.config("my_gitlab") do |db_id, redirect_uri|
  #   MultiAuth::Provider::GenericOAuth2.new(
  #     provider_name: "GitLab",
  #     redirect_uri: redirect_uri,
  #     key: ENV["GITLAB_CLIENT_ID"],
  #     secret: ENV["GITLAB_CLIENT_SECRET"],
  #     **config,
  #   )
  # end
  # ```
  #
  # Returns a NamedTuple with the discovered configuration parameters
  def self.discover(domain : String) : NamedTuple(
    site: String,
    authorize_url: String,
    token_url: String,
    authentication_scheme: String,
    user_profile_url: String?,
    scopes: String,
  )
    # Ensure domain has a scheme
    domain = domain.downcase
    domain = "https://#{domain}" unless domain.starts_with?("http://") || domain.starts_with?("https://")

    # Fetch OAuth2 metadata via well-known discovery
    metadata = MultiAuth::Discovery.fetch_oauth2_metadata(domain)

    # Parse the base site URL
    site_uri = URI.parse(metadata.issuer)
    site = "#{site_uri.scheme}://#{site_uri.host}"
    site += ":#{site_uri.port}" if site_uri.port && site_uri.port != 80 && site_uri.port != 443

    # Extract authorization and token endpoints as paths
    auth_uri = URI.parse(metadata.authorization_endpoint)
    token_uri = URI.parse(metadata.token_endpoint)

    authorize_url = auth_uri.path || "/oauth/authorize"
    token_url = token_uri.path || "/oauth/token"

    # Determine authentication scheme from supported methods
    auth_scheme = if methods = metadata.token_endpoint_auth_methods_supported
                    if methods.includes?("client_secret_post")
                      "request_body"
                    elsif methods.includes?("client_secret_basic")
                      "http_basic"
                    else
                      "request_body" # Default
                    end
                  else
                    "request_body" # Default if not specified
                  end

    # Get userinfo endpoint if available
    user_profile_url = metadata.userinfo_endpoint

    # Build default scopes from supported scopes
    scopes = if supported_scopes = metadata.scopes_supported
               # Common scopes that are usually safe to request
               common_scopes = ["openid", "profile", "email"]
               available = supported_scopes & common_scopes
               available.empty? ? "openid" : available.join(" ")
             else
               "openid profile email"
             end

    {
      site:                  site,
      authorize_url:         authorize_url,
      token_url:             token_url,
      authentication_scheme: auth_scheme,
      user_profile_url:      user_profile_url,
      scopes:                scopes,
    }
  end
end
