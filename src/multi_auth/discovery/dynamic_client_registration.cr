require "http/client"
require "json"

module MultiAuth::Discovery
  enum TokenEndpointAuthMethod
    None
    ClientSecretPost
    ClientSecretBasic
  end

  struct ClientRegistrationRequest
    include JSON::Serializable

    getter client_name : String
    getter redirect_uris : Array(String)
    getter grant_types : Array(String)?
    getter response_types : Array(String)?
    getter token_endpoint_auth_method : TokenEndpointAuthMethod? = TokenEndpointAuthMethod::None
    getter scope : String? = nil

    def initialize(
      @client_name,
      @redirect_uris,
      @grant_types,
      @response_types,
      @token_endpoint_auth_method,
      @scope,
    )
    end
  end

  struct ClientRegistrationResponse
    include JSON::Serializable

    getter client_id : String
    getter client_secret : String?
    getter client_id_issued_at : Int64?
    getter client_secret_expires_at : Int64?
    getter registration_access_token : String?
    getter registration_client_uri : String?
    getter token_endpoint_auth_method : TokenEndpointAuthMethod?
    getter redirect_uris : Array(String)?
  end

  # https://datatracker.ietf.org/doc/html/rfc7591
  def self.perform_dynamic_client_registration(metadata : OAuth2Metadata, registration : ClientRegistrationRequest) : ClientRegistrationResponse
    endpoint = metadata.registration_endpoint
    raise "No registration_endpoint provided" unless endpoint

    uri = URI.parse(endpoint)
    headers = HTTP::Headers{
      "Content-Type" => "application/json",
    }
    response = HTTP::Client.post(uri, headers, registration.to_json)

    unless response.status.success?
      raise "Client registration failed: #{response.status_code} - #{response.body}"
    end

    ClientRegistrationResponse.from_json(response.body)
  end
end
