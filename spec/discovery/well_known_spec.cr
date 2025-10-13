require "../spec_helper"

describe MultiAuth::Discovery::OAuth2Metadata do
  it "obtains oauth2 metadata for a service" do
    WebMock.stub(:get, "https://gitlab.com/.well-known/oauth-authorization-server")
      .to_return(body: %({"issuer":"https://gitlab.com","authorization_endpoint":"https://gitlab.com/oauth/authorize","token_endpoint":"https://gitlab.com/oauth/token","revocation_endpoint":"https://gitlab.com/oauth/revoke","introspection_endpoint":"https://gitlab.com/oauth/introspect","userinfo_endpoint":"https://gitlab.com/oauth/userinfo","jwks_uri":"https://gitlab.com/oauth/discovery/keys","scopes_supported":["api","read_api","read_user","create_runner","manage_runner","k8s_proxy","self_rotate","read_repository","write_repository","read_registry","write_registry","read_virtual_registry","write_virtual_registry","read_observability","write_observability","ai_features","sudo","admin_mode","read_service_ping","openid","profile","email","ai_workflows","user:*"],"response_types_supported":["code"],"response_modes_supported":["query","fragment","form_post"],"grant_types_supported":["authorization_code","password","client_credentials","device_code","refresh_token"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"claim_types_supported":["normal"],"claims_supported":["iss","sub","aud","exp","iat","sub_legacy","name","nickname","preferred_username","email","email_verified","website","profile","picture","groups","groups_direct","https://gitlab.org/claims/groups/owner","https://gitlab.org/claims/groups/maintainer","https://gitlab.org/claims/groups/developer"],"code_challenge_methods_supported":["plain","S256"]}))

    meta = MultiAuth::Discovery.fetch_oauth2_metadata("https://gitlab.com/")
    meta.issuer.should eq "https://gitlab.com"
  end

  describe ".discover" do
    it "discovers OAuth2 configuration from well-known endpoint" do
      WebMock.stub(:get, "https://gitlab.com/.well-known/oauth-authorization-server")
        .to_return(body: {
          issuer:                                "https://gitlab.com",
          authorization_endpoint:                "https://gitlab.com/oauth/authorize",
          token_endpoint:                        "https://gitlab.com/oauth/token",
          userinfo_endpoint:                     "https://gitlab.com/oauth/userinfo",
          scopes_supported:                      ["openid", "profile", "email", "api", "read_user"],
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
        }.to_json)

      config = MultiAuth::Discovery.discover("gitlab.com")

      config[:site].should eq("https://gitlab.com")
      config[:authorize_url].should eq("/oauth/authorize")
      config[:token_url].should eq("/oauth/token")
      config[:user_profile_url].should eq("https://gitlab.com/oauth/userinfo")
      config[:authentication_scheme].should eq("request_body")
      config[:scopes].should eq("openid profile email")
    end

    it "handles domains with scheme" do
      WebMock.stub(:get, "https://example.com/.well-known/oauth-authorization-server")
        .to_return(body: {
          issuer:                 "https://example.com",
          authorization_endpoint: "https://example.com/auth",
          token_endpoint:         "https://example.com/token",
          scopes_supported:       ["openid"],
        }.to_json)

      config = MultiAuth::Discovery.discover("https://example.com")

      config[:site].should eq("https://example.com")
      config[:authorize_url].should eq("/auth")
      config[:token_url].should eq("/token")
    end

    it "uses http_basic scheme when client_secret_basic is preferred" do
      WebMock.stub(:get, "https://auth.example.com/.well-known/oauth-authorization-server")
        .to_return(body: {
          issuer:                                "https://auth.example.com",
          authorization_endpoint:                "https://auth.example.com/authorize",
          token_endpoint:                        "https://auth.example.com/token",
          token_endpoint_auth_methods_supported: ["client_secret_basic"],
        }.to_json)

      config = MultiAuth::Discovery.discover("auth.example.com")

      config[:authentication_scheme].should eq("http_basic")
    end

    it "defaults to request_body when no auth methods specified" do
      WebMock.stub(:get, "https://simple.example.com/.well-known/oauth-authorization-server")
        .to_return(body: {
          issuer:                 "https://simple.example.com",
          authorization_endpoint: "https://simple.example.com/authorize",
          token_endpoint:         "https://simple.example.com/token",
        }.to_json)

      config = MultiAuth::Discovery.discover("simple.example.com")

      config[:authentication_scheme].should eq("request_body")
    end

    it "can be used to initialize GenericOAuth2" do
      WebMock.stub(:get, "https://auth.test.com/.well-known/oauth-authorization-server")
        .to_return(body: {
          issuer:                 "https://auth.test.com",
          authorization_endpoint: "https://auth.test.com/oauth/authorize",
          token_endpoint:         "https://auth.test.com/oauth/token",
          userinfo_endpoint:      "https://auth.test.com/api/user",
          scopes_supported:       ["openid", "profile", "email"],
        }.to_json)

      config = MultiAuth::Discovery.discover("auth.test.com")

      # Use discovered config to initialize provider
      MultiAuth.config("discovered_oauth2") do |db_id, redirect_uri|
        MultiAuth::Provider::GenericOAuth2.new(
          provider_name: "discovered-#{db_id}",
          redirect_uri: redirect_uri,
          key: "client_id",
          secret: "client_secret",
          site: config[:site],
          authorize_url: config[:authorize_url],
          token_url: config[:token_url],
          authentication_scheme: config[:authentication_scheme],
          user_profile_url: config[:user_profile_url] || "",
          scopes: config[:scopes],
          info_mappings: {
            "uid"   => "id",
            "name"  => "name",
            "email" => "email",
          }
        )
      end

      uri = MultiAuth.make("discovered_oauth2", "/callback", "test-id").authorize_uri

      uri.should contain("https://auth.test.com/oauth/authorize")
      uri.should contain("client_id=client_id")
      uri.should contain("redirect_uri=%2Fcallback")
      uri.should contain("scope=openid+profile+email")
    end
  end
end
