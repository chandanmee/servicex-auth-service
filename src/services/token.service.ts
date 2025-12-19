import * as jwt from "jsonwebtoken";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";

export const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN || "15m";
export const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN || "30d";

export function createAccessToken(payload: Record<string, any>) {
  const secret = (process.env.JWT_SECRET || "dev_secret") as jwt.Secret;
  return jwt.sign(payload, secret, { expiresIn: ACCESS_TOKEN_EXPIRES_IN } as any);
}

export function createRefreshTokenPair() {
  const tokenId = uuidv4();
  const raw = tokenId + "." + crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(raw).digest("hex");
  return { raw, tokenId, tokenHash };
}

export function hashToken(rawToken: string) {
  return crypto.createHash("sha256").update(rawToken).digest("hex");
}
