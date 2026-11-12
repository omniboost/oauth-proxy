# Oauth Proxy

This proxy is created to allow multiple clients (programs, servers) to use the
same Oauth token to be used simultaneously and keeping the latest (refresh)
token in sync in multiple processes.

This is a proxy specifically for Oauth token calls. It intercepts calls to the
token endpoint of a Oauth provider. The proxy keeps a local database of the
tokens and expire times. Whenever a token is to expire, the proxy refreshes the
token with a call to the original provider endpoint and stores the new tokens
(refresh token and access token) centrally. So is ensured every client uses the
same refresh token, access token and expire time. The proxy takes care of making
calls to the original token endpoint.


```
       +----------+
       |          |
       |  Oauth   |
       | provider |
       |          |
       +----+-----+
            ^
            |
            v
       +----+-----+
       |          |
       |  Oauth   |
       |  proxy   |
       |          |
       +-+------+-+
         ^      ^
         |      |
     +---+      +---+
     |              |
+----+-----+   +----+-----+
|          |   |          |
|  Oauth   |   |  Oauth   |
|  client  |   |  client  |
|          |   |          |
+----------+   +----------+
```

## Installation

```
go get github.com/omniboost/oauth-proxy/bin/oauth-proxy
```

## Grafana events

Request logs and secret read/write events are buffered and sent to Loki in a
single push at the end of each token or revoke request, before the handler
returns. This makes
sure they're not lost when Lambda freezes the execution environment after the
response.

Each request owns its own buffer; events are never shared between requests.
Buffering does not perform network I/O; sending the batch at the end of the
handler waits for Loki, with a 5-second timeout.

### Secret reads and writes

Every read and write of a stored token is logged, so we know how often secrets
are read from and written to the database (IN-5149). Token values are never
logged.

| Operation | When |
| --- | --- |
| `read` | a token row is looked up: once per token request (also when it isn't found or expired) and refresh token revoke |
| `write` | a token is saved and its access or refresh token changed (`refresh_token_changed`, `access_token_changed`), or a token is revoked; also when that failed |

The lookup while saving a token is part of the write and isn't counted, so a
refresh counts as one read and one write and a code exchange as one write. Changes to only e.g. the expiry don't count as a
write.

All events have `app` (the provider) and `grant_type` as structured metadata.
Examples:

```
# reads and writes per hour
sum by (operation) (count_over_time({service="oauth-proxy", event="secret"} [1h]))

# reads per provider per minute
sum by (app) (count_over_time({service="oauth-proxy", event="secret", operation="read"} [1m]))
```
