// src/middlewares/auth.middleware.js
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const tokenService = require('../services/token.service');

// If you later switch to RS256, update this to read public key:
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

function verifyJWT(req, res, next) {
  try {
    const auth = req.headers.authorization || req.headers.Authorization;
    if (!auth) return res.status(401).json({ message: 'No auth header' });
    const parts = auth.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ message: 'Invalid auth header' });
    const token = parts[1];
    // Use tokenService.verifyAccessToken if you added it; otherwise use jwt directly
    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
    // normalize into req.user
    req.user = { sub: payload.sub || payload.id || payload.userId, roles: payload.roles || [] };
    return next();
  } catch (err) {
    console.error('[auth.middleware] unexpected error', err);
    return res.status(401).json({ message: 'Unauthorized' });
  }
}

module.exports = { verifyJWT };
