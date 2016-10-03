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

const payload = {
  userID: 34,
  admin: true
};

describe('jwt-auth', () => {
  it('should be able to change default options', () => {
    jwtAuth.init({
      tokenExpirationInSeconds: 100
    });
    let options = jwtAuth.getOptions();
    expect(options).to.be.an('object');
    expect(options.tokenExpirationInSeconds).to.equal(100);
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

  it('should be able to obtain a new token given a valid token', (done) => {
    jwtAuth.init({
      tokenExpirationInSeconds: 5
    });
    jwtAuth.loadCerts('./server.pem', './server.pub')
      .then((result) => {
        jwtAuth.createToken(payload)
          .then((token) => {
            jwtAuth.verifyToken(token)
              .then((result) => {
                // delay refresh token because a token refreshed within the same
                // time second will return the same token value.
                setTimeout(() => {
                  jwtAuth.refreshToken(token)
                    .then((newToken) => {
                      expect(newToken).to.be.a('string');
                      expect(newToken).to.not.equal(token);
                      done();
                    });
                }, 1500);
              });
          });
      });
  });

  it('should fail to obtain a new token given an invalid token', (done) => {
    jwtAuth.init({
      tokenExpirationInSeconds: 1
    });
    jwtAuth.loadCerts('./server.pem', './server.pub')
      .then((result) => {
        jwtAuth.createToken(payload)
          .then((token) => {
            jwtAuth.verifyToken(token)
              .then((result) => {
                // delay refresh token so that original token ends up expiring.
                setTimeout(() => {
                  jwtAuth.refreshToken(token)
                  .catch((err) => {
                    expect(err.message.indexOf('jwt expired')).to.be.above(-1);
                    done();
                  });
                }, 1500);
              });
          });
      });
  });

});
