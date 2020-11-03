defmodule Ueberauth.Strategy.OIDCTest do
  use ExUnit.Case
  doctest Ueberauth.Strategy.OIDC

  import Mock
  import Plug.Conn
  import Plug.Test

  @config Application.fetch_env!(:ueberauth, Ueberauth)[:providers][:provider] |> elem(1)

  setup_with_mocks([
    {OAuth2.Client, [:passthrough],
     [
       get_token: &oauth2_get_token/2,
       get: &oauth2_get/2
     ]}
  ]) do
    :ok
  end

  defp oauth2_get_token(client, code: "successful_auth") do
    {:ok, %{client | token: OAuth2.AccessToken.new("successful_auth")}}
  end

  defp oauth2_get_token(_client, code: "failed_auth") do
    {:error,
     %OAuth2.Response{
       status_code: 400,
       body: %{
         "error" => "invalid_request"
       }
     }}
  end

  defp oauth2_get_token(client, code: "failed_userinfo") do
    {:ok, %{client | token: OAuth2.AccessToken.new("failed_userinfo")}}
  end

  defp oauth2_get(%{token: %{access_token: "successful_auth"}}, _url) do
    {:ok,
     %OAuth2.Response{
       status_code: 200,
       body: %{
         "sub" => "authenticated_user",
         "email" => "authenticated_user@example.com"
       }
     }}
  end

  defp oauth2_get(%{token: %{access_token: "failed_userinfo"}}, _url) do
    {:error,
     %OAuth2.Response{
       status_code: 400,
       body: %{
         "error" => "invalid_request"
       }
     }}
  end

  test "redirects to correct auth URI" do
    routes = Ueberauth.init()

    conn =
      conn(:get, "/auth/provider")
      |> Ueberauth.call(routes)

    assert conn.status == 302
    assert [location] = get_resp_header(conn, "location")

    uri = URI.parse(location)
    assert @config[:authorization_endpoint] == %{uri | query: nil} |> to_string()

    query = URI.decode_query(uri.query)
    assert query["scope"] == @config[:scopes]
    assert "/auth/provider/callback" == URI.parse(query["redirect_uri"]).path
    assert @config[:client_id] == query["client_id"]
    assert "code" == query["response_type"]
  end

  test "fetches token and userinfo, and assigns to ueberauth_auth" do
    routes = Ueberauth.init()

    conn =
      conn(:get, "/auth/provider/callback", code: "successful_auth", state: "state1")
      |> Ueberauth.call(routes)

    assert %Plug.Conn{assigns: %{ueberauth_auth: auth}} = conn
    assert "successful_auth" == auth.credentials.token
    assert "authenticated_user@example.com" == auth.info.email
    assert "authenticated_user" == auth.uid
    assert :provider == auth.provider
    assert Ueberauth.Strategy.OIDC == auth.strategy
  end

  test "fails when token endpoint returns an error" do
    routes = Ueberauth.init()

    conn =
      conn(:get, "/auth/provider/callback", code: "failed_auth", state: "state1")
      |> Ueberauth.call(routes)

    assert %Plug.Conn{assigns: %{ueberauth_failure: failure}} = conn
    assert conn.assigns[:ueberauth_auth] == nil
  end

  test "fails when userinfo endpoint returns an error" do
    routes = Ueberauth.init()

    conn =
      conn(:get, "/auth/provider/callback", code: "failed_userinfo", state: "state1")
      |> Ueberauth.call(routes)

    assert %Plug.Conn{assigns: %{ueberauth_failure: failure}} = conn
    assert conn.assigns[:ueberauth_auth] == nil
  end
end
