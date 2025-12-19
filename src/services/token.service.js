const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');


const JWT_SECRET = process.env.JWT_SECRET;

const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN || '15m';
const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN || '30d';

// sign short-lived JWT access token
function createAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256', expiresIn: ACCESS_TOKEN_EXPIRES_IN });
}
// returns an object: { raw: "<tokenId>.<randomHex>", tokenId, tokenHash }
function createRefreshTokenPair() {
  const tokenId = uuidv4(); // short unique id
  const raw = tokenId + '.' + crypto.randomBytes(32).toString('hex'); // client receives this
  const tokenHash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, tokenId, tokenHash };
}

function hashToken(rawToken) {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}


module.exports = {
  createAccessToken,
  createRefreshTokenPair,
  hashToken,
  ACCESS_TOKEN_EXPIRES_IN,
  REFRESH_TOKEN_EXPIRES_IN
};