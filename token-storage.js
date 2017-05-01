'use strict';

const Promise = require('bluebird');
const Cacher = require('fwsp-cacher');

class MemoryTokenStorageManager {
  constructor() {
    this.usedTokens = [];
  }

  isTokenUsed(hash) {
    return Promise.resolve(hash)
      .tap(hash => {
        if (this.usedTokens.includes(hash)) {
          throw new Error('Token Already Used');
        }
      });
  }

  markTokenUsed(hash) {
    return this.isTokenUsed(hash)
      .then(hash => {
        this.usedTokens.push(hash);
      });
  }
}

class RedisTokenStorageManager {
  constructor(config) {
    this.cacher = new Cacher();
    this.cacher.init(config);
    this.cacher.setCachePrefix(config.cachePrefix || 'fwsp-jwt-auth-token');
  }

  isTokenUsed(hash) {
    return this.cacher.getData(hash)
      .then(data => {
        if (data === hash) {
          throw new Error('Token Already Used');
        }
        return hash;
      });
  }

  markTokenUsed(hash) {
    return this.isTokenUsed(hash)
      .then(hash => this.cacher.setData(hash, hash, 63072000));
  }
}

module.exports = {
  MemoryTokenStorageManager,
  RedisTokenStorageManager
};
