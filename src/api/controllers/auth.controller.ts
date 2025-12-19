import { Request, Response, NextFunction } from "express";
import bcrypt from "bcryptjs";
import User from "../../models/UserCredential";
import * as tokenService from "../../services/token.service";
import { extractDeviceInfo } from "../../middlewares/deviceInfo";

const MAX_FAILED_ATTEMPTS = Number(process.env.MAX_FAILED_ATTEMPTS || 5);
const LOCKOUT_MINUTES = Number(process.env.LOCKOUT_MINUTES || 15);

function parseDurationToDate(durationStr: string) {
  const num = Number(durationStr.replace(/\D/g, "")) || 30;
  if (durationStr.endsWith("d")) return new Date(Date.now() + num * 24 * 60 * 60 * 1000);
  if (durationStr.endsWith("h")) return new Date(Date.now() + num * 60 * 60 * 1000);
  if (durationStr.endsWith("m")) return new Date(Date.now() + num * 60 * 1000);
  return new Date(Date.now() + num * 24 * 60 * 60 * 1000);
}

export async function register(req: Request, res: Response, next: NextFunction) {
  try {
    const { email, password, firstName, lastName } = req.body as any;
    if (!email || !password) return res.status(400).json({ message: "email & password required" });
    const exists = await (User as any).findOne({ email }).lean();
    if (exists) return res.status(409).json({ message: "Email already registered" });
    const passwordHash = await bcrypt.hash(password, 12);
    const user = new (User as any)({
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
    } catch (err: any) {
      if (err && err.code === 11000 && err.keyPattern && err.keyPattern.email) {
        return res.status(409).json({ message: "Email already registered" });
      }
      throw err;
    }
  } catch (err) {
    next(err);
  }
}

export async function login(req: Request, res: Response, next: NextFunction) {
  try {
    const { email, password } = req.body as any;
    const device = extractDeviceInfo(req);
    const user = await (User as any).findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      return res.status(403).json({ message: "Account temporarily locked due to multiple failed login attempts" });
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      const updates = { $inc: { failedLoginAttempts: 1 } };
      const updated = await (User as any).findByIdAndUpdate(user._id, updates, { new: true }).select("failedLoginAttempts");
      if (updated.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
        const lockUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
        await (User as any).findByIdAndUpdate(user._id, { $set: { lockedUntil: lockUntil } });
      }
      return res.status(401).json({ message: "Invalid credentials" });
    }
    const now = new Date();
    await (User as any).findByIdAndUpdate(user._id, {
      $set: { lastLogin: now, failedLoginAttempts: 0, lockedUntil: null }
    });
    const { raw: refreshRaw, tokenId, tokenHash } = tokenService.createRefreshTokenPair();
    const expiresAt = parseDurationToDate(process.env.REFRESH_TOKEN_EXPIRES_IN || "30d");
    const sessionEntry = {
      tokenId,
      tokenHash,
      createdAt: now,
      expiresAt,
      lastUsedAt: now,
      device
    };
    await (User as any).findByIdAndUpdate(user._id, { $push: { sessionTokens: sessionEntry } });
    const accessToken = tokenService.createAccessToken({ sub: user._id.toString(), roles: user.roles });
    return res.json({
      accessToken,
      refreshToken: refreshRaw,
      tokenType: "Bearer",
      expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || "15m"
    });
  } catch (err) {
    next(err);
  }
}

export async function refresh(req: Request, res: Response, next: NextFunction) {
  try {
    const { refreshToken } = req.body as any;
    if (!refreshToken) return res.status(400).json({ message: "refreshToken required" });
    const parts = refreshToken.split(".");
    if (parts.length < 2) return res.status(401).json({ message: "Invalid refresh token format" });
    const tokenId = parts[0];
    const refreshHash = tokenService.hashToken(refreshToken);
    const now = new Date();
    const user = await (User as any).findOne({
      "sessionTokens.tokenId": tokenId,
      "sessionTokens.tokenHash": refreshHash,
      "sessionTokens.expiresAt": { $gt: now }
    });
    if (!user) {
      const foundById = await (User as any).findOne({ "sessionTokens.tokenId": tokenId });
      if (foundById) {
        await (User as any).updateOne({ _id: foundById._id }, { $set: { sessionTokens: [] } });
        return res.status(401).json({ message: "Invalid refresh token (revoked all sessions)" });
      }
      return res.status(401).json({ message: "Invalid refresh token" });
    }
    const { raw: newRaw, tokenId: newTokenId, tokenHash: newTokenHash } = tokenService.createRefreshTokenPair();
    const newExpires = parseDurationToDate(process.env.REFRESH_TOKEN_EXPIRES_IN || "30d");
    const pullRes = await (User as any).updateOne(
      { _id: user._id },
      { $pull: { sessionTokens: { tokenId, tokenHash: refreshHash } } }
    );
    if (!pullRes.modifiedCount) {
      return res.status(401).json({ message: "Invalid or expired refresh token" });
    }
    await (User as any).updateOne(
      { _id: user._id },
      { $push: { sessionTokens: { tokenId: newTokenId, tokenHash: newTokenHash, createdAt: now, expiresAt: newExpires, lastUsedAt: now, device: {} } } }
    );
    const accessToken = tokenService.createAccessToken({ sub: user._id.toString(), roles: user.roles });
    return res.json({
      accessToken,
      refreshToken: newRaw,
      tokenType: "Bearer",
      expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || "15m"
    });
  } catch (err) {
    next(err);
  }
}

export async function logout(req: Request, res: Response, next: NextFunction) {
  try {
    const { refreshToken } = req.body as any;
    if (!refreshToken) return res.status(400).json({ message: "refreshToken required" });
    const parts = refreshToken.split(".");
    if (parts.length < 2) return res.status(400).json({ message: "Invalid refresh token format" });
    const tokenId = parts[0];
    await (User as any).updateOne({ "sessionTokens.tokenId": tokenId }, { $pull: { sessionTokens: { tokenId } } });
    return res.json({ message: "Logged out" });
  } catch (err) {
    next(err);
  }
}

export async function me(req: Request, res: Response, next: NextFunction) {
  try {
    if (!req.user || !req.user.sub) return res.status(401).json({ message: "Not authenticated" });
    const userId = req.user.sub;
    const user = await (User as any).findById(userId).select("email firstName lastName roles isEmailVerified avatar").lean();
    if (!user) return res.status(404).json({ message: "User not found" });
    return res.json(user);
  } catch (err) {
    next(err);
  }
}

export async function listSessions(req: Request, res: Response, next: NextFunction) {
  try {
    const userId = req.params.id;
    const user = await (User as any).findById(userId).select("sessionTokens firstName lastName email");
    if (!user) return res.status(404).json({ message: "User not found" });
    return res.json({ id: user._id, email: user.email, sessions: user.sessionTokens });
  } catch (err) {
    next(err);
  }
}

export async function revokeSession(req: Request, res: Response, next: NextFunction) {
  try {
    const { userId, tokenId } = req.body as any;
    await (User as any).updateOne({ _id: userId }, { $pull: { sessionTokens: { tokenId } } });
    return res.json({ message: "session revoked" });
  } catch (err) {
    next(err);
  }
}
