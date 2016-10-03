'use strict';
// JSON Web Token Authentication

const Promise = require('bluebird');
const jwt = require('jsonwebtoken');
const fs = require('fs');

class JWTToken {
  constructor() {
    this.privateCert = null;
    this.publicCert = null;
    this.options = {
      tokenExpirationInSeconds: 3600
    };
  }

  /**
  * @name init
  * @summary initialize JWTToken
  * @param {object} options - overrides for default options
  */
  init(options) {
    this.options = Object.assign(this.options, options);
  }

  /**
  * @name getOptions
  * @summary Retrieve the module options
  * @return {object} options - module options
  */
  getOptions() {
    return this.options;
  }

  /**
  * @name loadCerts
  * @summary Load security certificates
  * @param {string} privateCertPath - path to private certificate
  * @param {string} publicCertPath - path to public certificate
  * @return {object} promise -
  */
  loadCerts(privateCertPath, publicCertPath) {
    return new Promise((resolve, reject) => {
      try {
        if (privateCertPath) {
          this.privateCert = fs.readFileSync(privateCertPath);
        }
        if (publicCertPath) {
          this.publicCert = fs.readFileSync(publicCertPath);
        }
        resolve(true);
      } catch (e) {
        reject(e);
      }
    });
  }

  /**
  * @name getPrivateCert
  * @summary Return the loaded private cert
  * @return {string} private cert or null
  */
  getPrivateCert() {
    return this.privateCert;
  }

  /**
  * @name getPublicCert
  * @summary Return the loaded public cert
  * @return {string} private cert or null
  */
  getPublicCert() {
    return this.publicCert;
  }

  /**
  * @name createToken
  * @summary Create a signed JSON web token
  * @param {object} payload - user level payload to merge into token
  * @return {object} promise -
  */
  createToken(payload) {
    return new Promise((resolve, reject) => {
      if (!this.privateCert) {
        reject(new Error('Private certificate wasn\'t loaded in loadCerts call.'));
        return;
      }
      payload = Object.assign(payload, {
        issuer: 'urn:auth',
        exp: Math.floor(Date.now() / 1000) + this.options.tokenExpirationInSeconds
      });
      jwt.sign(payload, this.privateCert, { algorithm: 'RS256' }, (err, token) => {
        if (err) {
          reject(err);
        } else {
          resolve(token);
        }
      });
    });
  }

  /**
  * @name verifyToken
  * @summary Verify a token.
  * @param {string} token - JSON web token
  * @return {object} promise - if successful resolves to the decoded payload
  */
  verifyToken(token) {
    return new Promise((resolve, reject) => {
      if (!this.publicCert) {
        reject(new Error('Public certificate wasn\'t loaded in loadCerts call.'));
        return;
      }
      jwt.verify(token, this.publicCert, (err, decoded) => {
        if (err) {
          reject(err);
        } else {
          resolve(decoded);
        }
      });
    });
  }

  /**
  * @name refreshToken
  * @summary Refresh a valid token
  * @param {string} token - JSON web token
  * @return {object} promise -
  */
  refreshToken(token) {
    return new Promise((resolve, reject) => {
      return this.verifyToken(token)
        .then((data) => {
          return this.createToken(data)
            .then((newToken) => {
              resolve(newToken);
            })
            .catch((err) => {
              reject(err);
            });
        })
        .catch((err) => {
          reject(err);
        });
    });
  }
}

module.exports = new JWTToken();
