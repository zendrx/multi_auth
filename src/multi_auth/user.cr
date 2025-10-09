require "oauth"
require "oauth2"

class MultiAuth::User
  def initialize(
    @provider, @uid, @name, @raw_json, @access_token,
    @email = nil,
    @nickname = nil,
    @first_name = nil,
    @last_name = nil,
    @location = nil,
    @description = nil,
    @image = nil,
    @phone = nil,
    @urls = nil,
  )
  end

  getter provider : String
  getter uid : String
  getter name : String?
  getter raw_json : String
  getter access_token : OAuth::AccessToken | OAuth2::AccessToken

  property email : String?
  property nickname : String?
  property first_name : String?
  property last_name : String?
  property location : String?
  property description : String?
  property image : String?
  property phone : String?
  property urls : Hash(String, String)?
end
