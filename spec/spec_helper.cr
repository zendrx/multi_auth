require "spec"
require "webmock"
require "../src/multi_auth"
require "../src/multi_auth/providers/*"
require "../src/multi_auth/discovery/*"

Spec.before_each &->WebMock.reset

MultiAuth.config("google", "google_id", "google_secret")
MultiAuth.config("github", "github_id", "github_secret")
MultiAuth.config("gitlab", "gitlab_id", "gitlab_secret")
MultiAuth.config("facebook", "facebook_id", "facebook_secret")
MultiAuth.config("vk", "vk_id", "vk_secret")
MultiAuth.config("x_twitter", "x_twitter_client_id", "x_twitter_client_secret")
MultiAuth.config("restream", "restream_id", "restream_secret")
MultiAuth.config("discord", "discord_id", "discord_secret")
