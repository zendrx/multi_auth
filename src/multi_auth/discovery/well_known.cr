require "http/client"
require "json"
require "uri"

module MultiAuth::Discovery
  struct OAuth2Metadata
    include JSON::Serializable

    getter issuer : String
    getter authorization_endpoint : String
    getter token_endpoint : String
    getter jwks_uri : String?

    # Optional extensions and discovery parameters
    getter registration_endpoint : String?
    getter userinfo_endpoint : String?
    getter revocation_endpoint : String?
    getter introspection_endpoint : String?

    # PKCE and supported values
    getter scopes_supported : Array(String)?
    getter response_types_supported : Array(String)?
    getter response_modes_supported : Array(String)?
    getter grant_types_supported : Array(String)?
    getter token_endpoint_auth_methods_supported : Array(String)?
    getter token_endpoint_auth_signing_alg_values_supported : Array(String)?
    getter service_documentation : String?

    getter ui_locales_supported : Array(String)?
    getter op_policy_uri : String?
    getter op_tos_uri : String?

    getter code_challenge_methods_supported : Array(String)?
    getter claims_supported : Array(String)?
    getter subject_types_supported : Array(String)?
    getter id_token_signing_alg_values_supported : Array(String)?
    getter id_token_encryption_alg_values_supported : Array(String)?
    getter id_token_encryption_enc_values_supported : Array(String)?

    getter request_object_signing_alg_values_supported : Array(String)?
    getter request_parameter_supported : Bool?
    getter request_uri_parameter_supported : Bool?
    getter require_request_uri_registration : Bool?

    # these are some good defaults, assuming
    def initialize(base_uri : URI)
      @issuer = "#{base_uri.scheme}://#{base_uri.host}"
      @authorization_endpoint = base_uri + "/oauth/authorize"
      @token_endpoint = base_uri + "/oauth/token"
      @revocation_endpoint = base_uri + "/oauth/revoke"
      @introspection_endpoint = base_uri + "/oauth/introspect"
    end
  end

  # grabs oauth endpoint metadata as per https://datatracker.ietf.org/doc/html/rfc8414
  def self.fetch_oauth2_metadata(base_url : String, max_redirects : Int32 = 5) : OAuth2Metadata
    uri = URI.parse(base_url)
    uri.path = "/.well-known/oauth-authorization-server"
    visited = Set(String).new

    max_redirects.times do
      raise "Redirect loop detected" if visited.includes?(uri.to_s)
      visited << uri.to_s

      response = HTTP::Client.get(uri)

      case response.status_code
      when 200
        return OAuth2Metadata.from_json(response.body)
      when 301, 302, 303, 307, 308
        location = response.headers["Location"]?
        raise "Redirect without Location header" unless location

        new_uri = URI.parse(location)

        # Make relative redirects absolute
        unless new_uri.absolute?
          new_uri.scheme = uri.scheme
          new_uri.host = uri.host
        end

        uri = new_uri
      else
        raise "Failed to fetch metadata: #{response.status_code} #{response.status}"
      end
    end

    raise "Too many redirects (limit: #{max_redirects})"
  end
end
