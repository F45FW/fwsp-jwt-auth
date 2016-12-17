# jwt-auth

[![npm version](https://badge.fury.io/js/fwsp-jwt-auth.svg)](https://badge.fury.io/js/fwsp-jwt-auth) <span class="badge-npmdownloads"><a href="https://npmjs.org/package/fwsp-jwt-auth" title="View this project on NPM"><img src="https://img.shields.io/npm/dm/fwsp-jwt-auth.svg" alt="NPM downloads" /></a></span> [![npm](https://img.shields.io/npm/l/fwsp-jwt-auth.svg)]()

[JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token) Authentication.

### Using jwt-auth
`jwt-auth` is intended for use by servers / services and relies on external RSA digital certificates in order to carry out its operations.
Use the supplied `keygen.sh` script if you need to create a public/private key pair.

Some services might use a private certificate to create a JSON Web Token, while another service might just use the public certificate to validate the authenticity of a token.

Load jwt-auth as you would normally and load the private and public certificates.  You can replace the loadCerts parameters with `null` if you only need to load a private or public certificate.

```javascript
const jwtAuth = require('fwsp-jwt-auth');
jwtAuth.loadCerts('./server.pem', './server.pub');
```

Overriding default options:

The jwt-auth init member can be used to override default values. At this time there's only one default value: `tokenExpirationInSeconds` which as a default set to 3600 seconds or one hour.

To set a token expiration to only 10 seconds:

```javascript
jwtAuth.init({
  tokenExpirationInSeconds: 10
});
```
> Note: when using refreshToken, the token will be refreshed to the value set in the initialization options.

To create a JWT token:

```javascript
const payload = {
  userID: 34,
  admin: true
};
jwtAuth.createToken(payload)
  .then((token) => {
    // token is now ready for use.
  });
```

To verify a JWT token:

```javascript
jwtAuth.verifyToken(token)
  .then((response) => {
    // if valid, the response is decoded JWT payload, see verify token response below.
  });
```

Verify token response
```javascript
{
  "userID": 34,
  "admin": true,
  "issuer": "urn:auth",
  "exp": 1466614755,
  "iat": 1466614754
}
```

To refresh a valid token:

```javascript
jwtAuth.refreshToken(token)
  .then((newToken) => {
    // if original token was valid then a newToken is returned.
  });
```

To retrieve a hash of an existing token:

```javascript
let hash = jwtAuth.getTokenHash(token);
```

This is useful when implementing a token management scheme.

### Creating private and public certificates
You can use the supplied `keygen.sh` script to create certificates for use with jwt-auth.

```shell
$ ./keygen.sh
```

### Tests
This project includes mocha/chai tests.  Make sure you have mocha installed globally.

```shell
$ npm install mocha -g
```

Then run:

```shell
$ npm test
```
