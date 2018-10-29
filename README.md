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
