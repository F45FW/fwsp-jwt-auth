'use strict';
// JSON Web Token Authentication

const Promise = require('bluebird');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const crypto = require('crypto');

const {
  TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH
} = require('./consts');

class JWTToken {
  constructor() {
    this.privateCert = null;
    this.publicCert = null;
    this.options = {
      tokenExpirationInSeconds: 3600,
      refreshTokenExpirationInSeconds: 3600
    };
    this.tokenStorageManager = null;
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

  setTokenStorageManager(manager) {
    this.tokenStorageManager = manager;
  }

  /**
  * @name createToken
  * @summary Create a signed JSON web token
  * @param {object} payload - user level payload to merge into token
  * @param {number} type - type of token (access or refresh) to generate
  * @return {object} promise -
  */
  createToken(payload, type = TOKEN_TYPE_ACCESS) {
    return new Promise((resolve, reject) => {
      if (!this.privateCert) {
        reject(new Error('Private certificate wasn\'t loaded in loadCerts call.'));
        return;
      }

      let tokenLifetime = type == TOKEN_TYPE_ACCESS ?
        this.options.tokenExpirationInSeconds :
        this.options.refreshTokenExpirationInSeconds;
      payload = Object.assign(payload, {
        issuer: 'urn:auth',
        exp: Math.floor(Date.now() / 1000) + tokenLifetime,
        token_type: type
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

  createAccessToken(payload) {
    return this.createToken(payload, TOKEN_TYPE_ACCESS);
  }

  createRefreshToken(payload) {
    return this.createToken(payload, TOKEN_TYPE_REFRESH);
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
  * @name executeRefreshToken
  * @summary Refresh a valid token
  * @param {string} token - JSON web token
  * @return {object} promise -
  */
  executeRefreshToken(token) {
    return this.verifyToken(token)
      .tap(data => { // Tap is used here to not alter the return value of the verify token promise
        if (data.token_type !== TOKEN_TYPE_REFRESH) {
          throw new Error('Invalid token type');
        }
      })
      .tap(() => // Tap is used here to not alter the return value of the verify token promise
        this.checkIfRefreshTokenUsed(token)
          .then(hash => this.markRefreshTokenUsed(hash))
      );
  }

  /**
  * @name getTokenHash
  * @summary Return a Sha1 hash of the token
  * @param {string} token - JSON web token
  * @return {string} sha1 hash - in string hex format
  */
  getTokenHash(token) {
    let sha1 = crypto.createHash('sha1');
    sha1.update(token);
    return sha1.digest('hex');
  }

  /**
   * @description Helper function to determine if a refresh token has already been used
   * @param {string} token - JWT refresh token to check
   * @returns {Promise} Promise resolved with token hash if not used, rejected otherwise
   */
  checkIfRefreshTokenUsed(token) {
    let hash = this.getTokenHash(token);
    return this.tokenStorageManager ? this.tokenStorageManager.isTokenUsed(hash) : Promise.resolve(hash);
  }

  /**
   * @description Marks a JWT refresh token hash as used
   * @param {string} hash - JWT refresh token hash
   * @returns {Promise} Promise resolved when token has been marked as used
   */
  markRefreshTokenUsed(hash) {
    return this.tokenStorageManager ? this.tokenStorageManager.markTokenUsed(hash) : Promise.resolve();
  }
}

module.exports = new JWTToken();
