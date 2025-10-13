require "../spec_helper"

describe MultiAuth::Provider::GenericOAuth2 do
  # Simulate a database record configuration
  describe "with custom provider configuration" do
    it "generates authorize uri" do
      MultiAuth.config("user_oauth2") do |redirect_uri, db_id|
        MultiAuth::Provider::GenericOAuth2.new(
          provider_name: "oauth2-#{db_id}",
          redirect_uri: redirect_uri,
          key: "custom_client_id",
          secret: "custom_client_secret",
          site: "https://auth.example.com",
          authorize_url: "/oauth/authorize",
          token_url: "/oauth/token",
          authentication_scheme: "request_body",
          user_profile_url: "https://api.example.com/user/me",
          scopes: "read:user read:email",
          info_mappings: {
            "uid"         => "id",
            "name"        => "full_name",
            "email"       => "email",
            "nickname"    => "username",
            "image"       => "avatar_url",
            "description" => "bio",
          }
        )
      end

      uri = MultiAuth.make("user_oauth2", "/callback", "database-id").authorize_uri

      uri.should contain("https://auth.example.com/oauth/authorize")
      uri.should contain("client_id=custom_client_id")
      uri.should contain("redirect_uri=%2Fcallback")
      uri.should contain("scope=read%3Auser+read%3Aemail")
    end

    it "fetches and maps user data" do
      MultiAuth.config("user_oauth2") do |redirect_uri, db_id|
        MultiAuth::Provider::GenericOAuth2.new(
          provider_name: "oauth2-#{db_id}",
          redirect_uri: redirect_uri,
          key: "custom_client_id",
          secret: "custom_client_secret",
          site: "https://auth.example.com",
          authorize_url: "/oauth/authorize",
          token_url: "/oauth/token",
          authentication_scheme: "request_body",
          user_profile_url: "https://api.example.com/user/me",
          scopes: "read:user read:email",
          info_mappings: {
            "uid"         => "id",
            "name"        => "full_name",
            "email"       => "email",
            "nickname"    => "username",
            "image"       => "avatar_url",
            "description" => "bio",
          }
        )
      end

      WebMock.stub(:post, "https://auth.example.com/oauth/token")
        .to_return(body: {
          access_token: "test_token_123",
          token_type:   "bearer",
          expires_in:   3600,
          scope:        "read:user read:email",
        }.to_json)

      WebMock.stub(:get, "https://api.example.com/user/me")
        .to_return(body: {
          id:         "12345",
          full_name:  "John Doe",
          email:      "john@example.com",
          username:   "johndoe",
          avatar_url: "https://example.com/avatars/johndoe.jpg",
          bio:        "Software developer",
        }.to_json)

      user = MultiAuth.make("user_oauth2", "/callback", "database-id").user({"code" => "auth_code_123"})

      user.provider.should eq("oauth2-database-id")
      user.uid.should eq("12345")
      user.name.should eq("John Doe")
      user.email.should eq("john@example.com")
      user.nickname.should eq("johndoe")
      user.image.should eq("https://example.com/avatars/johndoe.jpg")
      user.description.should eq("Software developer")
      user.access_token.should_not be_nil
    end

    it "handles nested JSON paths" do
      MultiAuth.config("nested_oauth2") do |redirect_uri, db_id|
        MultiAuth::Provider::GenericOAuth2.new(
          provider_name: "oauth2-#{db_id}",
          redirect_uri: redirect_uri,
          key: "nested_client_id",
          secret: "nested_client_secret",
          site: "https://auth.nested.com",
          authorize_url: "/authorize",
          token_url: "/token",
          authentication_scheme: "request_body",
          user_profile_url: "https://api.nested.com/v1/user",
          scopes: "profile",
          info_mappings: {
            "uid"      => "data.user.id",
            "name"     => "data.user.profile.full_name",
            "email"    => "data.user.contact.email",
            "nickname" => "data.user.username",
          }
        )
      end

      WebMock.stub(:post, "https://auth.nested.com/token")
        .to_return(body: {
          access_token: "nested_token",
          token_type:   "bearer",
          expires_in:   7200,
        }.to_json)

      WebMock.stub(:get, "https://api.nested.com/v1/user")
        .to_return(body: {
          data: {
            user: {
              id:       "999",
              username: "nesteduser",
              profile:  {
                full_name: "Nested User",
              },
              contact: {
                email: "nested@example.com",
              },
            },
          },
        }.to_json)

      user = MultiAuth.make("nested_oauth2", "/callback", "database-id").user({"code" => "nested_code"})

      user.provider.should eq("oauth2-database-id")
      user.uid.should eq("999")
      user.name.should eq("Nested User")
      user.email.should eq("nested@example.com")
      user.nickname.should eq("nesteduser")
    end

    it "handles multiple URL mappings" do
      MultiAuth.config("custom_oauth2") do |redirect_uri, db_id|
        raise "no oauth2 provider selected" unless db_id

        MultiAuth::Provider::GenericOAuth2.new(
          provider_name: db_id,
          redirect_uri: redirect_uri,
          key: "url_client_id",
          secret: "url_client_secret",
          site: "https://auth.url.com",
          authorize_url: "/authorize",
          token_url: "/token",
          authentication_scheme: "request_body",
          user_profile_url: "https://api.url.com/profile",
          scopes: "profile",
          info_mappings: {
            "uid"         => "id",
            "name"        => "name",
            "url_website" => "website",
            "url_blog"    => "blog_url",
            "url_github"  => "github_url",
          }
        )
      end

      WebMock.stub(:post, "https://auth.url.com/token")
        .to_return(body: {access_token: "url_token"}.to_json)

      WebMock.stub(:get, "https://api.url.com/profile")
        .to_return(body: {
          id:         "111",
          name:       "URL User",
          website:    "https://example.com",
          blog_url:   "https://blog.example.com",
          github_url: "https://github.com/example",
        }.to_json)

      user = MultiAuth.make("custom_oauth2", "/callback", "db-id").user({"code" => "url_code"})

      user.urls.should_not be_nil
      user.urls.not_nil!["website"].should eq("https://example.com")
      user.urls.not_nil!["blog"].should eq("https://blog.example.com")
      user.urls.not_nil!["github"].should eq("https://github.com/example")
    end
  end
end
