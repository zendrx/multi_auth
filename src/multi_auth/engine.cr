class MultiAuth::Engine
  def initialize(provider : String, redirect_uri : String)
    provider_class = MultiAuth::Providers.get(provider)
    key, secret = MultiAuth.configuration[provider]
    @provider = provider_class.new(redirect_uri, key, secret)
  end

  def initialize(@provider)
  end

  getter provider : Provider

  def authorize_uri(scope = nil, state = nil)
    provider.authorize_uri(scope, state)
  end

  def user(params : Enumerable({String, String})) : User
    provider.user(params.to_h)
  end
end
