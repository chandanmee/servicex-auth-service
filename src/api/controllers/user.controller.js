// src/api/controllers/user.controller.js
const User = require('../../models/UserCredential');

/**
 * GET /api/users/:id
 * Owner or admin can fetch a user's profile (safely filtered)
 */
exports.getUserById = async (req, res, next) => {
  try {
    const actor = req.user && req.user.sub;
    const actorRoles = (req.user && req.user.roles) || [];

    const targetId = req.params.id;
    if (!actor) return res.status(401).json({ message: 'Unauthorized' });

    // allow owner or admin
    if (actor !== targetId && !actorRoles.includes('admin')) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    const user = await User.findById(targetId)
      .select('email firstName lastName roles isEmailVerified avatar metadata')
      .lean();

    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json(user);
  } catch (err) { next(err); }
};

/**
 * GET /api/users/:id/sessions
 * List active sessions for the user (owner or admin).
 * Returns session metadata but NOT tokenHash.
 */
exports.listSessions = async (req, res, next) => {
  try {
    const actor = req.user && req.user.sub;
    const actorRoles = (req.user && req.user.roles) || [];
    const targetId = req.params.id;
    if (!actor) return res.status(401).json({ message: 'Unauthorized' });

    if (actor !== targetId && !actorRoles.includes('admin')) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    const user = await User.findById(targetId).select('sessionTokens firstName lastName email').lean();
    if (!user) return res.status(404).json({ message: 'User not found' });

    // remove tokenHash from each session for safety
    const sessions = (user.sessionTokens || []).map(s => {
      const { tokenHash, ...rest } = s;
      return rest;
    });

    return res.json({ id: user._id, email: user.email, sessions });
  } catch (err) { next(err); }
};

/**
 * POST /api/users/:id/sessions/revoke
 * Body: { tokenId: "<tokenId>" }
 * Owner or admin may revoke a single session.
 */
exports.revokeSession = async (req, res, next) => {
  try {
    const actor = req.user && req.user.sub;
    const actorRoles = (req.user && req.user.roles) || [];
    const targetId = req.params.id;
    const { tokenId } = req.body;
    if (!actor) return res.status(401).json({ message: 'Unauthorized' });

    if (actor !== targetId && !actorRoles.includes('admin')) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    if (!tokenId) return res.status(400).json({ message: 'tokenId required' });

    await User.updateOne({ _id: targetId }, { $pull: { sessionTokens: { tokenId } }, $set: { updatedBy: actor, updatedAt: new Date() } });
    return res.json({ message: 'session revoked' });
  } catch (err) { next(err); }
};


// PATCH /api/users/:id
// Update user info (firstName, lastName, avatar, metadata)
exports.updateUser = async (req, res, next) => {
  try {
    const actorId = req.user.sub;                 // logged-in user
    const actorRoles = req.user.roles || [];
    const targetId = req.params.id;

    // Allow only:
    // - user updating themselves
    // - admin updating anyone
    if (actorId !== targetId && !actorRoles.includes("admin")) {
      return res.status(403).json({ message: "Forbidden" });
    }

    // Allowed fields only
    const allowed = ["firstName", "lastName", "avatar", "metadata"];
    const updates = {};

    allowed.forEach((field) => {
      if (req.body[field] !== undefined) updates[field] = req.body[field];
    });

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: "Nothing to update" });
    }

    updates.updatedBy = actorId;
    updates.updatedAt = new Date();

    const updatedUser = await User.findByIdAndUpdate(
      targetId,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('email firstName lastName roles isEmailVerified avatar metadata');

    if (!updatedUser) return res.status(404).json({ message: "User not found" });

    return res.json(updatedUser);
  } catch (err) {
    next(err);
  }
};
