# OAuth 2.0 Authorization Server

This server provides authorization tokens to OAuth 2.0 clients requesting access to protected resources on a designated resource server.  Clients and resource servers can utilize public /.well-known/ endpoints for configuration details and keysets.

The authorization code grant type is supported along with HTTP Basic authentication for token requests, and Bearer authentication for user info requests

The server utilizes Elliptic Curve keysets and encodes payload using the ES256 algorithm.  Both the authorization code and access tokens are issued as self-encoded and signed JWTs containing necessary information.

A sample User is created who owns a client with the id "test-client".  Upon the clients attempted access to a protected resource, the User will be required to login and approve or deny access.  If access is approved, an authorization token will be issued along with a refresh token.

<br />
<p align="center">
<img width="523" alt="screenshot" src="https://user-images.githubusercontent.com/64601713/116919743-9389e080-ac06-11eb-859e-f05d09ab0589.png">
</p>

## Installation

Set required MySQL path and user information in application.properties.  
If running locally along with a local client or resource server, set the following hosts file line:
```bash
127.0.0.1 auth-server
```
Mac users can use this awesome hosts file tool: https://github.com/2ndalpha/gasmask

Then to run:
```bash
chmod +x gradlew
./gradlew run
```

## Usage

To simply view the server's current keyset, visit:  http://localhost:8081/oauth2/.well-known/jwks.json

To test with client application:  
Set up AuthClient info inside AuthServerDemoApplication->loadInitialData method, and point your client to http://auth-server:8081/oauth2/ for configuration discovery.

## Info

Feedback, advice, kind words are all accepted at any time :)

This server was written as a learning project and proof-of-concept.  
It is by no means complete, secure, or ready to be used for any production environment.

## License
[MIT](https://github.com/uuufo/auth-server-demo/blob/main/LICENSE)
