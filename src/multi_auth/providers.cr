class MultiAuth::Providers
  @@registry = {} of String => MultiAuth::Provider.class

  def self.register(name : String, klass : MultiAuth::Provider.class)
    @@registry[name] = klass
  end

  def self.get(name : String)
    raise MultiAuth::Exception.new("Provider #{name} not implemented") unless @@registry.has_key?(name)
    @@registry[name]
  end
end
