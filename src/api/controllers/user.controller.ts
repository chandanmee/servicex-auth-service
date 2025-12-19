import { Request, Response, NextFunction } from "express";
import User from "../../models/UserCredential";

export async function getUserById(req: Request, res: Response, next: NextFunction) {
  try {
    const actor = req.user && req.user.sub;
    const actorRoles = (req.user && req.user.roles) || [];
    const targetId = req.params.id;
    if (!actor) return res.status(401).json({ message: "Unauthorized" });
    if (actor !== targetId && !actorRoles.includes("admin")) {
      return res.status(403).json({ message: "Forbidden" });
    }
    const user = await (User as any).findById(targetId).select("email firstName lastName roles isEmailVerified avatar metadata").lean();
    if (!user) return res.status(404).json({ message: "User not found" });
    return res.json(user);
  } catch (err) {
    next(err);
  }
}

export async function listSessions(req: Request, res: Response, next: NextFunction) {
  try {
    const actor = req.user && req.user.sub;
    const actorRoles = (req.user && req.user.roles) || [];
    const targetId = req.params.id;
    if (!actor) return res.status(401).json({ message: "Unauthorized" });
    if (actor !== targetId && !actorRoles.includes("admin")) {
      return res.status(403).json({ message: "Forbidden" });
    }
    const user = await (User as any).findById(targetId).select("sessionTokens firstName lastName email").lean();
    if (!user) return res.status(404).json({ message: "User not found" });
    const sessions = (user.sessionTokens || []).map((s: any) => {
      const { tokenHash, ...rest } = s;
      return rest;
    });
    return res.json({ id: user._id, email: user.email, sessions });
  } catch (err) {
    next(err);
  }
}

export async function revokeSession(req: Request, res: Response, next: NextFunction) {
  try {
    const actor = req.user && req.user.sub;
    const actorRoles = (req.user && req.user.roles) || [];
    const targetId = req.params.id;
    const { tokenId } = req.body as any;
    if (!actor) return res.status(401).json({ message: "Unauthorized" });
    if (actor !== targetId && !actorRoles.includes("admin")) {
      return res.status(403).json({ message: "Forbidden" });
    }
    if (!tokenId) return res.status(400).json({ message: "tokenId required" });
    await (User as any).updateOne(
      { _id: targetId },
      { $pull: { sessionTokens: { tokenId } }, $set: { updatedBy: actor, updatedAt: new Date() } }
    );
    return res.json({ message: "session revoked" });
  } catch (err) {
    next(err);
  }
}

export async function updateUser(req: Request, res: Response, next: NextFunction) {
  try {
    const actorId = req.user!.sub;
    const actorRoles = req.user!.roles || [];
    const targetId = req.params.id;
    if (actorId !== targetId && !actorRoles.includes("admin")) {
      return res.status(403).json({ message: "Forbidden" });
    }
    const allowed = ["firstName", "lastName", "avatar", "metadata"];
    const updates: Record<string, any> = {};
    allowed.forEach((field) => {
      if ((req.body as any)[field] !== undefined) updates[field] = (req.body as any)[field];
    });
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: "Nothing to update" });
    }
    updates.updatedBy = actorId;
    updates.updatedAt = new Date();
    const updatedUser = await (User as any)
      .findByIdAndUpdate(targetId, { $set: updates }, { new: true, runValidators: true })
      .select("email firstName lastName roles isEmailVerified avatar metadata");
    if (!updatedUser) return res.status(404).json({ message: "User not found" });
    return res.json(updatedUser);
  } catch (err) {
    next(err);
  }
}
