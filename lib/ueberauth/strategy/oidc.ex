defmodule Ueberauth.Strategy.OIDC do
  @moduledoc """
  Documentation for `Ueberauth.Strategy.OIDC`.
  """

  use Ueberauth.Strategy
  require Logger

  alias Ueberauth.Auth.{Credentials, Extra, Info}

  @impl Ueberauth.Strategy
  def handle_request!(conn) do
    opts = oauth_options_from_conn(conn)
    scopes = oauth_scopes_from_conn(conn)
    redirect!(conn, Ueberauth.Strategy.OIDC.OAuth.authorize_url!(opts, scope: scopes))
  end

  @impl Ueberauth.Strategy
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    params = [code: code]
    opts = oauth_options_from_conn(conn)

    Ueberauth.Strategy.OIDC.OAuth.get_oidc_tokens(opts, params)
    |> fetch_user(conn)
  end

  @impl Ueberauth.Strategy
  def handle_cleanup!(conn) do
    conn
    |> put_private(:oidc_tokens, nil)
    |> put_private(:oidc_userinfo, nil)
  end

  @impl Ueberauth.Strategy
  def uid(conn) do
    uid_field =
      oauth_options_from_conn(conn)
      |> Keyword.get(:uid_field, "sub")

    conn.private.oidc_userinfo[uid_field]
  end

  @impl Ueberauth.Strategy
  def credentials(conn) do
    tokens = conn.private.oidc_tokens

    scopes =
      (tokens.other_params["scope"] || "")
      |> String.split(~r/\s+|\s*,\s*/)

    %Credentials{
      expires: !!tokens.expires_at,
      expires_at: tokens.expires_at,
      scopes: scopes,
      token_type: tokens.token_type,
      refresh_token: tokens.refresh_token,
      token: tokens.access_token
    }
  end

  @impl Ueberauth.Strategy
  def info(conn) do
    %Info{
      birthday: conn.private.oidc_userinfo["birthdate"],
      email: conn.private.oidc_userinfo["email"],
      first_name: conn.private.oidc_userinfo["given_name"],
      image: conn.private.oidc_userinfo["picture"],
      last_name: conn.private.oidc_userinfo["family_name"],
      name: conn.private.oidc_userinfo["name"],
      nickname: conn.private.oidc_userinfo["nickname"],
      phone: conn.private.oidc_userinfo["phone_number"]
    }
  end

  @impl Ueberauth.Strategy
  def extra(conn) do
    %Extra{
      raw_info: %{
        full_userinfo: conn.private.oidc_userinfo
      }
    }
  end

  defp oauth_options_from_conn(conn, opts \\ []) do
    request_options = [redirect_uri: callback_url(conn) |> adjust_forwarded_port(conn)]

    options(conn)
    |> mangle_config()
    |> Keyword.merge(request_options)
    |> Keyword.merge(opts)
  end

  defp oauth_scopes_from_conn(conn, opts \\ []) do
    opts = oauth_options_from_conn(conn, opts)

    case opts[:scopes] do
      list when is_list(list) -> Enum.join(list, " ")
      str when is_binary(str) -> str
      nil -> "openid"
    end
  end

  defp mangle_config(config) do
    config
    |> put_in([:authorize_url], config[:authorization_endpoint])
    |> put_in([:token_url], config[:token_endpoint])
  end

  defp adjust_forwarded_port(uri, conn) do
    uri = URI.parse(uri)

    forwarded_port =
      with [header | _] <- conn |> Plug.Conn.get_req_header("x-forwarded-port"),
           {port, _} <- Integer.parse(header) do
        port
      else
        _ -> uri.port
      end

    %{uri | port: forwarded_port}
    |> to_string
  end

  defp fetch_user({:ok, %{access_token: _} = tokens}, conn) do
    conn = put_private(conn, :oidc_tokens, tokens)

    conn
    |> oauth_options_from_conn(token: tokens)
    |> Ueberauth.Strategy.OIDC.OAuth.get_userinfo()
    |> ingest_userinfo(conn)
  end

  defp fetch_user({:error, error}, conn) do
    conn |> set_errors!([error("token_error", "Could not get token: #{inspect(error)}")])
  end

  defp ingest_userinfo({:ok, %OAuth2.Response{status_code: 401}}, conn) do
    conn |> set_errors!([error("userinfo_error", "access token unauthorized")])
  end

  defp ingest_userinfo({:ok, %OAuth2.Response{status_code: status_code, body: userinfo}}, conn)
       when status_code in 200..399 do
    conn
    |> put_private(:oidc_userinfo, userinfo)
  end

  defp ingest_userinfo({:error, error}, conn) do
    conn
    |> set_errors!([error("userinfo_error", "Could not retrieve Userinfo: #{inspect(error)}")])
  end
end
