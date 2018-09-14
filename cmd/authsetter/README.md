# Standalone Authsetter

Authsetter is a standalone reverse proxy application to set auth tokens on your products domain.
Running this server and pointing your domain towards it exposes the required '/as' endpoint that
proxies through to Fident to set authtokens in your domain.

```
usage: authsetter [<flags>]

Flags:
      --help     Show context-sensitive help (also try --help-long and --help-man).
  -t, --token-endpoint="https://authsetter.fident.io"  Set Fident token endpoint.
  -d, --dev      Enable developer Mode.
      --version  Show application version.
```
