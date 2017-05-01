'use strict';

require('./helpers/chai.js');

const {
  MemoryTokenStorageManager,
  RedisTokenStorageManager
} = require('../token-storage');

let tokenHash = 'abc';

describe('MemoryTokenStorageManager', () => {
  let manager;

  beforeEach(() => {
    manager = new MemoryTokenStorageManager();
  });

  it('should be able to tell that an unused token is unused', () => {
    let p = manager.isTokenUsed(tokenHash);

    return expect(p).to.eventually.equal(tokenHash);
  });

  it('should be able to mark an unused token as used', () => {
    let p = manager.markTokenUsed(tokenHash);

    return expect(p).to.be.fulfilled;
  });

  it('should be able to tell that a used token is used', () => {
    let p = manager.markTokenUsed(tokenHash)
      .then(() => manager.isTokenUsed(tokenHash));

    return expect(p).to.be.rejected;
  });

  it('should fail to mark a used token as used', () => {
    let p = manager.markTokenUsed(tokenHash)
      .then(() => manager.markTokenUsed(tokenHash));

    return expect(p).to.be.rejected;
  });
});

describe('RedisTokenStorageManager', () => {
  let manager;

  beforeEach(() => {
    let config = {
      url: 'localhost',
      port: 6379,
      db: 15,
      cachePrefix: `fwsp-jwt-auth-token-test-${Date.now()}`
    };
    manager = new RedisTokenStorageManager(config);
  });

  it('should be able to tell that an unused token is unused', () => {
    let p = manager.isTokenUsed(tokenHash);

    return expect(p).to.eventually.equal(tokenHash);
  });

  it('should be able to mark an unused token as used', () => {
    let p = manager.markTokenUsed(tokenHash);

    return expect(p).to.be.fulfilled;
  });

  it('should be able to tell that a used token is used', () => {
    let p = manager.markTokenUsed(tokenHash)
      .then(() => manager.isTokenUsed(tokenHash));

    return expect(p).to.be.rejected;
  });

  it('should fail to mark a used token as used', () => {
    let p = manager.markTokenUsed(tokenHash)
      .then(() => manager.markTokenUsed(tokenHash));

    return expect(p).to.be.rejected;
  });
});
