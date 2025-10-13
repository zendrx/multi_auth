# GenericOAuth2 Provider

The `GenericOAuth2` provider allows you to dynamically configure OAuth2 providers at runtime, making it perfect for database-driven multi-tenant applications where OAuth providers are configured by users.

## Features

- **Dynamic Configuration**: Configure providers from database records at runtime
- **Automatic Discovery**: Discover OAuth2 configuration from `.well-known/oauth-authorization-server` endpoints
- **Flexible Mapping**: Map any JSON structure to User fields using dot notation
- **Multiple URL Support**: Map multiple URL fields (website, blog, social links, etc.)
- **Nested JSON Support**: Access deeply nested fields like `data.user.profile.name`
- **Custom Authentication Schemes**: Supports `http_basic` and `request_body` authentication

## Usage

### Discovery Helper

The `discover` class method automatically fetches OAuth2 configuration from a domain's `.well-known/oauth-authorization-server` endpoint:

```crystal
require "multi_auth/providers/generic_oauth2"

# Discover configuration from GitLab
config = MultiAuth::Discovery.discover("gitlab.com")

# Returns a NamedTuple with:
# - site: "https://gitlab.com"
# - authorize_url: "/oauth/authorize"
# - token_url: "/oauth/token"
# - authentication_scheme: "request_body" or "http_basic"
# - user_profile_url: "https://gitlab.com/oauth/userinfo"
# - scopes: "openid profile email"

# Use the discovered config
MultiAuth.config("gitlab") do |db_id, redirect_uri|
  MultiAuth::Provider::GenericOAuth2.new(
    provider_name: "GitLab",
    redirect_uri: redirect_uri,
    key: ENV["GITLAB_CLIENT_ID"],
    secret: ENV["GITLAB_CLIENT_SECRET"],
    site: config[:site],
    authorize_url: config[:authorize_url],
    token_url: config[:token_url],
    authentication_scheme: config[:authentication_scheme],
    user_profile_url: config[:user_profile_url] || "",
    scopes: config[:scopes],
    info_mappings: {
      "uid"   => "sub",
      "name"  => "name",
      "email" => "email",
    }
  )
end
```

The discovery helper:
- Automatically adds `https://` scheme if not present
- Parses the issuer to extract the base site URL
- Extracts authorization and token endpoint paths
- Detects authentication scheme from supported methods
- Builds default scopes from common OpenID scopes (openid, profile, email)
- Returns userinfo endpoint if available

### Basic Setup

Use the factory method to dynamically create providers:

```crystal
# Example: Load configuration from database
MultiAuth.config("user_oauth2") do |database_id, redirect_uri|
  config = OAuthProviderConfig.find(database_id) # Your DB model

  MultiAuth::Provider::GenericOAuth2.new(
    provider_name: "oauth2-#{database_id}",
    redirect_uri: redirect_uri,
    key: config.client_id,
    secret: config.client_secret,
    site: config.site,
    authorize_url: config.authorize_url,
    token_url: config.token_url,
    authentication_scheme: config.authentication_scheme,
    user_profile_url: config.user_profile_url,
    scopes: config.scopes,
    info_mappings: config.info_mappings
  )
end
```

### Database Model Example

Your database model might look like:

```crystal
class OAuthProviderConfig
  attribute name : String                      # Display name: "My Custom OAuth"
  attribute client_id : String                 # OAuth client ID
  attribute client_secret : String             # OAuth client secret
  attribute site : String                      # Base URL: "https://oauth.example.com"
  attribute authorize_url : String             # Authorization endpoint: "/oauth/authorize"
  attribute token_url : String                 # Token endpoint: "/oauth/token"
  attribute authentication_scheme : String     # Auth scheme: "request_body" or "http_basic"
  attribute user_profile_url : String          # User info URL: "https://api.example.com/user"
  attribute scopes : String                    # Default scopes: "read:user read:email"
  attribute info_mappings : Hash(String, String) # Field mappings (see below)
end
```

### Info Mappings

The `info_mappings` hash maps MultiAuth User fields to JSON keys from the OAuth provider's user profile endpoint:

#### Basic Mapping

```crystal
info_mappings: {
  "uid"         => "id",           # User's unique ID
  "name"        => "full_name",    # Full name
  "email"       => "email",        # Email address
  "nickname"    => "username",     # Username/handle
  "first_name"  => "given_name",   # First name
  "last_name"   => "family_name",  # Last name
  "image"       => "avatar_url",   # Profile picture URL
  "description" => "bio",          # Biography/description
  "location"    => "city",         # Location/city
  "phone"       => "phone_number", # Phone number
}
```

#### Nested Field Mapping

Use dot notation to access nested fields:

```crystal
info_mappings: {
  "uid"      => "data.user.id",
  "name"     => "data.user.profile.full_name",
  "email"    => "data.user.contact.email",
  "nickname" => "data.user.username",
}
```

For this JSON structure:
```json
{
  "data": {
    "user": {
      "id": "123",
      "username": "johndoe",
      "profile": {
        "full_name": "John Doe"
      },
      "contact": {
        "email": "john@example.com"
      }
    }
  }
}
```

#### URL Mappings

Map multiple URLs using the `url_` prefix:

```crystal
info_mappings: {
  "uid"         => "id",
  "name"        => "name",
  "url_website" => "website",      # user.urls["website"]
  "url_blog"    => "blog_url",     # user.urls["blog"]
  "url_github"  => "github_url",   # user.urls["github"]
  "url_twitter" => "twitter_url",  # user.urls["twitter"]
}
```

### Complete Example

```crystal
# In your application initialization or controller
MultiAuth.config("generic_oauth2") do |database_id, redirect_uri|
  # Load from database
  config = OAuthProviderConfig.find(database_id)

  MultiAuth::Provider::GenericOAuth2.new(
    provider_name: config.name,
    redirect_uri: redirect_uri,
    key: config.client_id,
    secret: config.client_secret,
    site: config.site,
    authorize_url: config.authorize_url,
    token_url: config.token_url,
    authentication_scheme: config.authentication_scheme,
    user_profile_url: config.user_profile_url,
    scopes: config.scopes,
    info_mappings: config.info_mappings
  )
end

# Usage in your OAuth flow
# NOTE:: the optional ?: query param works in spider-gazelle and lucky frameworks
get "/auth/:provider/?:id" do
  provider = params["provider"]
  provider_id = params["id"]?
  engine = MultiAuth.make(provider, "/auth/#{provider}/callback/#{provider_id}", provider_id)

  redirect engine.authorize_uri
end

get "/auth/:provider/callback/?:id" do
  provider = params["provider"]
  provider_id = params["id"]?
  engine = MultiAuth.make(provider, "/auth/#{provider}/callback/#{provider_id}", provider_id)

  user = engine.user(params)

  # user.provider => "My Custom OAuth"
  # user.uid => "12345"
  # user.email => "user@example.com"
  # etc.
end
```

## Authentication Schemes

Two authentication schemes are supported:

1. **`request_body`** (default): Client credentials sent in the request body
   - Most common for modern OAuth2 providers
   - Recommended for web applications

2. **`http_basic`**: Client credentials sent via HTTP Basic Authentication
   - Legacy providers
   - Some enterprise OAuth implementations

## Field Reference

Available fields for mapping:

| Field | Description | Example JSON Key |
|-------|-------------|------------------|
| `uid` | Unique identifier (required) | `"id"`, `"user_id"` |
| `name` | Full name | `"full_name"`, `"displayName"` |
| `email` | Email address | `"email"` |
| `nickname` | Username/handle | `"username"`, `"login"` |
| `first_name` | First name | `"given_name"`, `"firstName"` |
| `last_name` | Last name | `"family_name"`, `"lastName"` |
| `image` | Profile picture URL | `"avatar_url"`, `"picture"` |
| `description` | Bio/description | `"bio"`, `"about"` |
| `location` | Location/city | `"location"`, `"city"` |
| `phone` | Phone number | `"phone"`, `"mobile"` |
| `url_*` | URLs (multiple allowed) | `"website"`, `"blog_url"` |

## Limitations

- Must always use the factory method with `MultiAuth.config(name) { ... }`
- Attempting to use `MultiAuth.config(name, key, secret)` will raise an error
