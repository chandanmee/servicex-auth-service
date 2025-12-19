// src/api/routes/auth.routes.js
const express = require('express');
const router = express.Router();

// auth controllers
const authController = require('../controllers/auth.controller');
// user controllers
const userController = require('../controllers/user.controller');

// multer upload middleware and avatar controller (local)
const upload = require('../../lib/multer'); // ensure this file exists
const avatarLocalCtrl = require('../controllers/avatar.local.controller');

// auth middleware
const { verifyJWT } = require('../../middlewares/auth.middleware');

// --- Auth endpoints ---
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/refresh', authController.refresh);
router.post('/logout', authController.logout);
router.get('/me', verifyJWT, authController.me);
router.get('/users/:id', verifyJWT, userController.getUserById);
router.get('/users/:id/sessions', verifyJWT, userController.listSessions);
router.post('/users/:id/sessions/revoke', verifyJWT, userController.revokeSession);
router.patch('/users/:id', verifyJWT, userController.updateUser);

// --- Avatar local upload (dev) ---
router.post('/users/:id/avatar', verifyJWT, upload.single('avatar'), avatarLocalCtrl.uploadLocal);

// Export router
module.exports = router;
