require "./multi_auth/*"

module MultiAuth
  {% begin %}
    VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}
  {% end %}

  @@configuration = Hash(String, Tuple(String, String)).new
  @@factories = Hash(String, Proc(String, MultiAuth::Provider)).new

  def self.make(provider : String, redirect_uri : String)
    if provider_factory = @@factories[provider]?
      provider_instance = provider_factory.call(redirect_uri)
      MultiAuth::Engine.new(provider_instance)
    else
      MultiAuth::Engine.new(provider, redirect_uri)
    end
  end

  def self.configuration
    @@configuration
  end

  def self.config(provider : String, key : String, secret : String)
    @@configuration[provider] = {key, secret}
  end

  def self.config(provider : String, &builder : Proc(String, MultiAuth::Provider))
    @@factories[provider] = builder
  end

  def self.config(provider : String, builder : Proc(String, MultiAuth::Provider))
    @@factories[provider] = builder
  end
end
