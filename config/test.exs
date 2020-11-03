import Config

config :ueberauth, Ueberauth,
  providers: [
    provider:
      {Ueberauth.Strategy.OIDC,
       [
         authorization_endpoint: "https://localhost:9999/auth",
         userinfo_endpoint: "https://localhost:9999/userinfo",
         scopes: "openid profile email",
         client_id: "test_client",
         client_secret: "test_secret"
       ]}
  ]
