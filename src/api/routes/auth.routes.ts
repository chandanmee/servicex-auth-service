import { Router } from "express";
import * as authController from "../controllers/auth.controller";
import * as userController from "../controllers/user.controller";
import upload from "../../lib/multer";
import { verifyJWT } from "../../middlewares/auth.middleware";
import { uploadLocal } from "../controllers/avatar.local.controller";

const router = Router();

router.post("/register", authController.register);
router.post("/login", authController.login);
router.post("/refresh", authController.refresh);
router.post("/logout", authController.logout);
router.get("/me", verifyJWT, authController.me);
router.get("/users/:id", verifyJWT, userController.getUserById);
router.get("/users/:id/sessions", verifyJWT, userController.listSessions);
router.post("/users/:id/sessions/revoke", verifyJWT, userController.revokeSession);
router.patch("/users/:id", verifyJWT, userController.updateUser);

router.post("/users/:id/avatar", verifyJWT, upload.single("avatar"), uploadLocal);

export default router;
