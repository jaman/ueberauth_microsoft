defmodule Ueberauth.Strategy.Microsoft do
  use Ueberauth.Strategy,
    uid_field: :id

  alias OAuth2.{Response, Error}
  alias Ueberauth.Auth.{Info, Credentials, Extra}
  alias Ueberauth.Strategy.Microsoft.OAuth

  @doc """
  Handles initial request for Microsoft authentication.
  """
  def handle_request!(conn) do
    authorize_url =
      conn.params
      |> Map.put(:redirect_uri, callback_url(conn))
      |> OAuth.authorize_url!(options(conn))

    redirect!(conn, authorize_url)
  end

  @doc """
  Handles the callback from Microsoft.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    opts = conn |> options() |> Keyword.put(:redirect_uri, callback_url(conn))
    client = OAuth.get_token!([code: code], opts)
    token = client.token

    case token.access_token do
      nil ->
        err = token.other_params["error"]
        desc = token.other_params["error_description"]
        set_errors!(conn, [error(err, desc)])

      _token ->
        fetch_user(conn, client)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:ms_token, nil)
    |> put_private(:ms_user, nil)
  end

  def uid(conn) do
    user =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.ms_user[user]
  end

  def credentials(conn) do
    token = conn.private.ms_token

    %Credentials{
      expires: token.expires_at != nil,
      expires_at: token.expires_at,
      scopes: token.other_params["scope"],
      token: token.access_token,
      refresh_token: token.refresh_token,
      token_type: token.token_type
    }
  end

  def info(conn) do
    user = conn.private.ms_user

    %Info{
      name: user["displayName"],
      email: user["mail"] || user["userPrincipalName"],
      first_name: user["givenName"],
      last_name: user["surname"]
    }
  end

  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.ms_token,
        user: conn.private.ms_user
      }
    }
  end

  defp fetch_user(conn, client) do
    conn = put_private(conn, :ms_token, client.token)
    [_, resp, _] = client.token.access_token
                   |> String.split(".")
    resp = resp
           |> Base.decode64!()
           |> Jason.decode!()

    put_private(conn, :ms_user, resp)

  end

  defp option(conn, key) do
    default = Keyword.get(default_options(), key)

    conn
    |> options
    |> Keyword.get(key, default)
  end
end
