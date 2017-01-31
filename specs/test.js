'use strict';

/**
 * Change into specs folder so that file loading works.
 */
process.chdir('./specs');

require('./helpers/chai.js');

const jwtAuth = require('../index.js');
jwtAuth.init({
  tokenExpirationInSeconds: 10
});

const {
  TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH
} = require('../consts');

const payload = {
  userID: 34,
  admin: true
};

const wait = ms => {
  return () => {
    return new Promise(resolve => {
      setTimeout(resolve, ms);
    });
  };
}

const now = () => {
  return Math.floor(Date.now() / 1000);
}

describe('jwt-auth', () => {
  it('should be able to change default options', () => {
    jwtAuth.init({
      tokenExpirationInSeconds: 100,
      refreshTokenExpirationInSeconds: 100
    });
    let options = jwtAuth.getOptions();
    expect(options).to.be.an('object');
    expect(options.tokenExpirationInSeconds).to.equal(100);
    expect(options.refreshTokenExpirationInSeconds).to.equal(100);
  });

  it('should fail to load misnamed cert', (done) => {
    jwtAuth.loadCerts('./fake.pem', null)
      .catch((err) => {
        expect(err.message.indexOf('ENOENT')).to.be.above(-1);
        done();
      });
  });

  it('should be able to load only private cert', (done) => {
    jwtAuth.init({
      tokenExpirationInSeconds: 10
    });
    jwtAuth.loadCerts('./server.pem', null)
      .then((result) => {
        expect(result).to.be.true;
        done();
      });
  });

  it('should be able to load only public cert', (done) => {
    jwtAuth.init({
      tokenExpirationInSeconds: 10
    });
    jwtAuth.loadCerts(null, './server.pub')
      .then((result) => {
        expect(result).to.be.true;
        done();
      });
  });

  it('should be able to load private and public certs', (done) => {
    jwtAuth.init({
      tokenExpirationInSeconds: 10
    });
    jwtAuth.loadCerts('./server.pem', './server.pub')
      .then((result) => {
        expect(result).to.be.true;
        done();
      });
  });

  it('should be able to create a new token', (done) => {
    jwtAuth.init({});
    jwtAuth.loadCerts('./server.pem', './server.pub')
      .then((result) => {
        jwtAuth.createToken(payload)
          .then((token) => {
            expect(token).to.be.a('string');
            expect(token).to.contain('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.');
            done();
          });
      });
  });

  it('should validate a valid token', (done) => {
    jwtAuth.init({
      tokenExpirationInSeconds: 1
    });
    jwtAuth.loadCerts('./server.pem', './server.pub')
      .then((result) => {
        jwtAuth.createToken(payload)
          .then((token) => {
            jwtAuth.verifyToken(token)
              .then((response) => {
                expect(response.userID).to.equal(34);
                expect(response.admin).to.be.true;
                done();
              });
          });
      });
  });

  it('should fail to validate a token that has been tampered with', (done) => {
    jwtAuth.init({});
    jwtAuth.loadCerts('./server.pem', './server.pub')
      .then((result) => {
        jwtAuth.createToken(payload)
          .then((token) => {
            // tamper with token
            token = token.substring(0, 99) + '*' + token.substring(100);
            return token;
          })
          .then((token) => {
            jwtAuth.verifyToken(token)
              .catch((err) => {
                expect(err.message.indexOf('invalid token')).to.be.above(-1);
                done();
              });
          });
      });
  });

  it('should fail to validate an expired token', (done) => {
    jwtAuth.init({
      tokenExpirationInSeconds: 1
    });
    jwtAuth.loadCerts('./server.pem', './server.pub')
      .then((result) => {
        jwtAuth.createToken(payload)
          .then((token) => {
            return token;
          })
          .then((token) => {
            // wait so token expires
            setTimeout(() => {
              jwtAuth.verifyToken(token)
                .catch((err) => {
                  expect(err.message.indexOf('jwt expired')).to.be.above(-1);
                  done();
                });
            }, 1500);
          });
      });
  });


  it('should be able to create an access token', () => {
    const ACCESS_EXP = 100;
    jwtAuth.init({
      tokenExpirationInSeconds: ACCESS_EXP,
      refreshTokenExpirationInSeconds: 1000
    });
    return jwtAuth.loadCerts('./server.pem', './server.pub')
      .then(() => jwtAuth.createAccessToken(payload))
      .then(token => jwtAuth.verifyToken(token))
      .then(res => {
        expect(res.token_type).to.equal(TOKEN_TYPE_ACCESS);
        expect(res.exp - now()).to.be.closeTo(ACCESS_EXP, 2);
      });
  });

  it('should be able to create a refresh token', () => {
    const REFRESH_EXP = 100;
    jwtAuth.init({
      tokenExpirationInSeconds: 1000,
      refreshTokenExpirationInSeconds: REFRESH_EXP
    });
    return jwtAuth.loadCerts('./server.pem', './server.pub')
      .then(() => jwtAuth.createRefreshToken(payload))
      .then(token => jwtAuth.verifyToken(token))
      .then(res => {
        expect(res.token_type).to.equal(TOKEN_TYPE_REFRESH);
        expect(res.exp - now()).to.be.closeTo(REFRESH_EXP, 2);
      });
  });

  it('should be able to execute a refresh of an unused refresh token', () => {
    jwtAuth.init({});
    let p = jwtAuth.loadCerts('./server.pem', './server.pub')
      .then(() => jwtAuth.createRefreshToken(payload))
      .then(token => jwtAuth.executeRefreshToken(token))
      .then(data => expect(data).to.contain.all.keys(payload))

    return expect(p).to.be.fulfilled;
  });

  it('should fail to execute a refresh of an access token', () => {
    jwtAuth.init({});
    let p = jwtAuth.loadCerts('./server.pem', './server.pub')
      .then(() => jwtAuth.createAccessToken(payload))
      .then(token => jwtAuth.executeRefreshToken(token));

    return expect(p).to.be.rejected;
  });

  it('should fail to execute a refresh of a used refresh token', () => {
    jwtAuth.init({});
    let p = jwtAuth.loadCerts('./server.pem', './server.pub')
      .then(() => jwtAuth.createRefreshToken(payload))
      .then(token => jwtAuth.executeRefreshToken(token));

    return expect(p).to.be.rejected;
  });

  it('should fail to execute a refresh of an expired refresh token', () => {
    jwtAuth.init({
      refreshTokenExpirationInSeconds: 1
    });

    let p = jwtAuth.loadCerts('./server.pem', './server.pub')
      .then(() => jwtAuth.createRefreshToken(payload))
      .tap(wait(1000))
      .then(token => jwtAuth.executeRefreshToken(token));

    return expect(p).to.be.rejected;
  });

  it('should return a token hash given a token', (done) => {
    jwtAuth.init({
      tokenExpirationInSeconds: 5
    });
    jwtAuth.loadCerts('./server.pem', './server.pub')
      .then((result) => {
        jwtAuth.createToken(payload)
          .then((token) => {
            let hash = jwtAuth.getTokenHash(token);
            expect(hash).to.be.a('string');
            expect(hash.length).to.equal(40);
            done();
          });
      });
  });

  it('should be able to check if an unused refresh token has been used', () => {
    jwtAuth.init({});

    let hash;
    let p = jwtAuth.loadCerts('./server.pem', './server.pub')
      .then(() => jwtAuth.createRefreshToken(payload))
      .tap(token => {
        hash = jwtAuth.getTokenHash(token);
      })
      .then(token => jwtAuth.checkIfRefreshTokenUsed(token))
      .tap(_hash => expect(_hash).to.equal(hash));

    return expect(p).to.be.fulfilled;
  });

  it('should be able to check if a used refresh token has been used', () => {
    jwtAuth.init({});

    let p = jwtAuth.loadCerts('./server.pem', './server.pub')
      .then(() => jwtAuth.createRefreshToken(payload))
      .then(token => jwtAuth.checkIfRefreshTokenUsed(token));

    return expect(p).to.be.rejected;
  });
});
