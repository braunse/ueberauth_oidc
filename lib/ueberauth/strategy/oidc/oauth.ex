defmodule Ueberauth.Strategy.OIDC.OAuth do
  @behaviour OAuth2.Strategy
  alias OAuth2.Client

  def client(opts \\ []) do
    opts
    |> validate_config!()
    |> Client.new()
    |> Client.put_serializer("application/json", Jason)
  end

  ### Ueberauth Interface

  def authorize_url!(opts \\ [], params \\ []) do
    client(opts)
    |> OAuth2.Client.authorize_url!(params)
  end

  def get_oidc_tokens(opts \\ [], params \\ []) do
    client(opts)
    |> OAuth2.Client.get_token(params)
    |> case do
      # Dialyzer says this can never match:

      # {:ok, %{token: %{access_token: nil} = token}} ->
      #   error = token.other_params["error"]
      #   error_description = token.other_params["error_description"]
      #   {:error, {error, error_description}}

      {:ok, %{token: token}} ->
        {:ok, token}

      {:error, %{body: body}} ->
        error = body["error"]
        error_description = body["error_description"]
        {:error, {error, error_description}}

      {:error, %OAuth2.Error{reason: reason}} ->
        {:error, {"oauth2_error", inspect(reason)}}
    end
  end

  def get_userinfo(opts) do
    client(opts)
    |> Client.put_header("Accept", "application/json")
    |> OAuth2.Client.get(Keyword.fetch!(opts, :userinfo_endpoint))
  end

  ### Behaviour Implementation

  def authorize_url(client, params) do
    client
    |> OAuth2.Strategy.AuthCode.authorize_url(params)
  end

  def get_token(client, params, headers) do
    client
    |> Client.put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end

  ### Configuration

  defp validate_config!(opts) do
    opts
  end
end
