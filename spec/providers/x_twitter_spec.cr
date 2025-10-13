require "../spec_helper"

describe MultiAuth::Provider::XTwitter do
  user_data = {
    data: {
      id:                "1234567890",
      name:              "X User",
      username:          "xuser",
      description:       "I'm an X user testing OAuth 2.0",
      profile_image_url: "https://pbs.twimg.com/profile_images/1234567890/photo.jpg",
    },
  }

  token_response = {
    token_type:    "bearer",
    expires_in:    7200,
    access_token:  "test_access_token_123",
    scope:         "tweet.read users.read offline.access",
    refresh_token: "test_refresh_token_456",
  }

  describe "#authorize_uri" do
    it "generates authorize uri with PKCE parameters" do
      provider = MultiAuth.make("x_twitter", "/callback")
      uri = provider.authorize_uri

      uri.should contain("https://x.com/i/oauth2/authorize")
      uri.should contain("client_id=x_twitter_client_id")
      uri.should contain("redirect_uri=%2Fcallback")
      uri.should contain("scope=tweet.read+users.read+offline.access")
      uri.should contain("code_challenge=")
      uri.should contain("code_challenge_method=S256")
    end
  end

  describe "#user" do
    it "successfully fetches user params" do
      WebMock.stub(:post, "https://api.x.com/2/oauth2/token")
        .to_return(body: token_response.to_json)

      WebMock.stub(:get, "https://api.x.com/2/users/me?user.fields=description,profile_image_url")
        .to_return(body: user_data.to_json)

      user = MultiAuth.make("x_twitter", "/callback").user({"code" => "test_authorization_code"})

      user.uid.should eq user_data[:data][:id]
      user.name.should eq user_data[:data][:name]
      user.nickname.should eq user_data[:data][:username]
      user.description.should eq user_data[:data][:description]
      user.image.should eq user_data[:data][:profile_image_url]

      user.provider.should eq "x_twitter"
      user.raw_json.should_not be_nil
      user.access_token.should_not be_nil
    end
  end
end
