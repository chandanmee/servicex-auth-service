import { Request, Response, NextFunction } from "express";
import * as jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

export function verifyJWT(req: Request, res: Response, next: NextFunction) {
  try {
    const auth = (req.headers.authorization || (req.headers as any).Authorization) as string | undefined;
    if (!auth) return res.status(401).json({ message: "No auth header" });
    const parts = auth.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer") return res.status(401).json({ message: "Invalid auth header" });
    const token = parts[1];
    let payload: any;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
    req.user = { sub: payload.sub || payload.id || payload.userId, roles: payload.roles || [] };
    return next();
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
}
