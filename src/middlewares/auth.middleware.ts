import { Request, Response, NextFunction } from "express";
import * as jwt from "jsonwebtoken";
import User from "../models/UserCredential";
import * as tokenService from "../services/token.service";

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const REFRESH_COOKIE_NAME = "refreshToken";
const ACCESS_COOKIE_NAME = "accessToken";

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const, 
  path: "/"
};

function parseDurationToDate(durationStr: string) {
  const num = Number(durationStr.replace(/\D/g, "")) || 30;
  if (durationStr.endsWith("d")) return new Date(Date.now() + num * 24 * 60 * 60 * 1000);
  if (durationStr.endsWith("h")) return new Date(Date.now() + num * 60 * 60 * 1000);
  if (durationStr.endsWith("m")) return new Date(Date.now() + num * 60 * 1000);
  return new Date(Date.now() + num * 24 * 60 * 60 * 1000);
}

export async function verifyJWT(req: Request, res: Response, next: NextFunction) {
  try {
    let token: string | undefined = undefined;

    // 1. Check Authorization header
    const auth = (req.headers.authorization || (req.headers as any).Authorization) as string | undefined;
    if (auth && auth.startsWith("Bearer ")) {
      token = auth.split(" ")[1];
    }

    // 2. Check Cookie (fallback)
    if (!token && req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }

    // If we have a token, try to verify it
    if (token) {
      try {
        const payload: any = jwt.verify(token, JWT_SECRET);
        req.user = { sub: payload.sub || payload.id || payload.userId, roles: payload.roles || [] };
        return next();
      } catch (err) {
        // Token expired or invalid, fall through to refresh logic
      }
    }

    // 3. Auto-Refresh Logic
    // If we are here, either no token was found OR the token was invalid/expired
    // We check for a valid refresh token in cookies
    const refreshToken = req.cookies[REFRESH_COOKIE_NAME];
    if (!refreshToken) {
      return res.status(401).json({ message: "No auth token found" });
    }

    // Verify refresh token
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
      // Possible reuse detection?
      const foundById = await (User as any).findOne({ "sessionTokens.tokenId": tokenId });
      if (foundById) {
        // Revoke all sessions for security
        await (User as any).updateOne({ _id: foundById._id }, { $set: { sessionTokens: [] } });
      }
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    // Rotate tokens
    const { raw: newRaw, tokenId: newTokenId, tokenHash: newTokenHash } = tokenService.createRefreshTokenPair();
    const newExpires = parseDurationToDate(process.env.REFRESH_TOKEN_EXPIRES_IN || "30d");

    // Remove old token
    await (User as any).updateOne(
      { _id: user._id },
      { $pull: { sessionTokens: { tokenId, tokenHash: refreshHash } } }
    );

    // Add new token
    await (User as any).updateOne(
      { _id: user._id },
      { $push: { sessionTokens: { tokenId: newTokenId, tokenHash: newTokenHash, createdAt: now, expiresAt: newExpires, lastUsedAt: now, device: {} } } }
    );

    const accessToken = tokenService.createAccessToken({ sub: user._id.toString(), roles: user.roles });

    // Set new cookies
    res.cookie(ACCESS_COOKIE_NAME, accessToken, {
      ...COOKIE_OPTIONS,
      expires: new Date(Date.now() + 15 * 60 * 1000)
    });
    res.cookie(REFRESH_COOKIE_NAME, newRaw, {
      ...COOKIE_OPTIONS,
      expires: newExpires
    });

    // Attach user to request
    req.user = { sub: user._id.toString(), roles: user.roles };
    return next();

  } catch (err) {
    console.error("Auth middleware error:", err);
    return res.status(401).json({ message: "Unauthorized" });
  }
}

export function requireRole(role: string | string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user || !req.user.roles) {
      return res.status(401).json({ message: "Not authenticated" });
    }
    const requiredRoles = Array.isArray(role) ? role : [role];
    const hasRole = req.user.roles.some((r: string) => requiredRoles.includes(r));
    if (!hasRole) {
      return res.status(403).json({ message: "Forbidden: Insufficient permissions" });
    }
    next();
  };
}
