const bcrypt = require('bcryptjs');
const User = require('../../models/UserCredential');
const tokenService = require('../../services/token.service');
const { extractDeviceInfo } = require('../../middlewares/deviceInfo');

const MAX_FAILED_ATTEMPTS = Number(process.env.MAX_FAILED_ATTEMPTS || 5);
const LOCKOUT_MINUTES = Number(process.env.LOCKOUT_MINUTES || 15);
// parseDurationToDate: parse duration string to Date object
function parseDurationToDate(durationStr) {
  // very small parser for '30d', '15m', '12h'
  const num = Number(durationStr.replace(/\D/g, '')) || 30;
  if (durationStr.endsWith('d')) return new Date(Date.now() + num * 24 * 60 * 60 * 1000);
  if (durationStr.endsWith('h')) return new Date(Date.now() + num * 60 * 60 * 1000);
  if (durationStr.endsWith('m')) return new Date(Date.now() + num * 60 * 1000);
  return new Date(Date.now() + num * 24 * 60 * 60 * 1000);
}

// register: create new user account
exports.register = async (req, res, next) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'email & password required' });

    // Basic pre-check (not enough by itself due to race)
    const exists = await User.findOne({ email }).lean();
    if (exists) return res.status(409).json({ message: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, 12);

    // Try create. Rely on DB unique index to handle race conditions.
    const user = new User({
      email,
      passwordHash,
      firstName,
      lastName,
      createdBy: null,
      updatedBy: null
    });

    try {
      const saved = await user.save();
      return res.status(201).json({ id: saved._id, email: saved.email });
    } catch (err) {
      // Handle duplicate key error from Mongo (race condition)
      if (err && err.code === 11000 && err.keyPattern && err.keyPattern.email) {
        return res.status(409).json({ message: 'Email already registered' });
      }
      throw err; // rethrow otherwise
    }
  } catch (err) {
    next(err);
  }
};

// login: authenticate user and issue tokens
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const device = extractDeviceInfo(req);

    const user = await User.findOne({ email });
    if (!user) {
      // generic message - do not leak existence
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // check locked
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      return res.status(403).json({ message: 'Account temporarily locked due to multiple failed login attempts' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      // increment failed attempts atomically
      const updates = { $inc: { failedLoginAttempts: 1 } };
      let updated = await User.findByIdAndUpdate(user._id, updates, { new: true }).select('failedLoginAttempts');
      if (updated.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
        const lockUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
        await User.findByIdAndUpdate(user._id, { $set: { lockedUntil: lockUntil } });
      }
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // successful login: reset failed attempts & set lastLogin
    const now = new Date();
    await User.findByIdAndUpdate(user._id, {
      $set: { lastLogin: now, failedLoginAttempts: 0, lockedUntil: null }
    });

    // create tokens (with tokenId)
    const { raw: refreshRaw, tokenId, tokenHash } = tokenService.createRefreshTokenPair();
    const expiresAt = parseDurationToDate(process.env.REFRESH_TOKEN_EXPIRES_IN || '30d');

    // push session token atomically
    const sessionEntry = {
      tokenId,
      tokenHash,
      createdAt: now,
      expiresAt,
      lastUsedAt: now,
      device: device
    };

    await User.findByIdAndUpdate(user._id, { $push: { sessionTokens: sessionEntry } });

    // issue access token
    const accessToken = tokenService.createAccessToken({ sub: user._id.toString(), roles: user.roles });

    return res.json({
      accessToken,
      refreshToken: refreshRaw,
      tokenType: 'Bearer',
      expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || '15m'
    });
  } catch (err) { next(err); }
};
// refresh: rotate refresh token pair
exports.refresh = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ message: 'refreshToken required' });

    // expected format tokenId.raw
    const parts = refreshToken.split('.');
    if (parts.length < 2) return res.status(401).json({ message: 'Invalid refresh token format' });
    const tokenId = parts[0];
    const refreshHash = tokenService.hashToken(refreshToken);
    const now = new Date();

    // atomically find user with matching tokenId AND tokenHash AND unexpired entry
    const user = await User.findOne({
      'sessionTokens.tokenId': tokenId,
      'sessionTokens.tokenHash': refreshHash,
      'sessionTokens.expiresAt': { $gt: now }
    });

    if (!user) {
      // check if tokenId exists but expired or hash mismatch to detect reuse
      const foundById = await User.findOne({ 'sessionTokens.tokenId': tokenId });
      if (foundById) {
        // tokenId exists but hash didn't match or expired -> possible token theft -> optionally revoke all sessions
        console.warn('[auth][refresh] tokenId presented but hash mismatch or expired, revoking all sessions for user:', foundById._id.toString());
        // Revoke all sessions for safety (policy decision)
        await User.updateOne({ _id: foundById._id }, { $set: { sessionTokens: [] } });
        return res.status(401).json({ message: 'Invalid refresh token (revoked all sessions)' });
      }
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    // rotate: perform $pull then $push in separate steps to avoid path collision on sessionTokens
    const { raw: newRaw, tokenId: newTokenId, tokenHash: newTokenHash } = tokenService.createRefreshTokenPair();
    const newExpires = parseDurationToDate(process.env.REFRESH_TOKEN_EXPIRES_IN || '30d');

    const pullRes = await User.updateOne(
      { _id: user._id },
      { $pull: { sessionTokens: { tokenId, tokenHash: refreshHash } } }
    );
    if (!pullRes.modifiedCount) {
      return res.status(401).json({ message: 'Invalid or expired refresh token' });
    }
    await User.updateOne(
      { _id: user._id },
      { $push: { sessionTokens: { tokenId: newTokenId, tokenHash: newTokenHash, createdAt: now, expiresAt: newExpires, lastUsedAt: now, device: {} } } }
    );

    // issue new access token
    const accessToken = tokenService.createAccessToken({ sub: user._id.toString(), roles: user.roles });

    return res.json({
      accessToken,
      refreshToken: newRaw,
      tokenType: 'Bearer',
      expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || '15m'
    });
  } catch (err) { next(err); }
};

// logout: revoke session by tokenId (idempotent)
exports.logout = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ message: 'refreshToken required' });
    const parts = refreshToken.split('.');
    if (parts.length < 2) return res.status(400).json({ message: 'Invalid refresh token format' });
    const tokenId = parts[0];

    await User.updateOne({ 'sessionTokens.tokenId': tokenId }, { $pull: { sessionTokens: { tokenId } } });

    return res.json({ message: 'Logged out' });
  } catch (err) { next(err); }
};

// me: get current user info
exports.me = async (req, res, next) => {
  try {
    if (!req.user || !req.user.sub) return res.status(401).json({ message: 'Not authenticated' });

    const userId = req.user.sub;
    const user = await User.findById(userId)
      .select('email firstName lastName roles isEmailVerified avatar')
      .lean();

    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json(user);
  } catch (err) { next(err); }
};


// list sessions for a user (admin or owner)
exports.listSessions = async (req, res, next) => {
  try {
    const userId = req.params.id; // admin: query any id; owner: use req.user.sub
    const user = await User.findById(userId).select('sessionTokens firstName lastName email');
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json({ id: user._id, email: user.email, sessions: user.sessionTokens });
  } catch (err) { next(err); }
};

// revokeSession: admin or owner can revoke any session
exports.revokeSession = async (req, res, next) => {
  try {
    const { userId, tokenId } = req.body; // or path params
    await User.updateOne({ _id: userId }, { $pull: { sessionTokens: { tokenId } } });
    return res.json({ message: 'session revoked' });
  } catch (err) { next(err); }
};

