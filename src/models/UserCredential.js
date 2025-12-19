// src/models/UserCredential.js
const mongoose = require('mongoose');

const RefreshTokenSchema = new mongoose.Schema({
  tokenHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
}, { _id: false });

const SessionTokenSchema = new mongoose.Schema({
  tokenId: { type: String, required: true },   // short id stored inside refresh token (see token.service)
  tokenHash: { type: String, required: true }, // hashed refresh token
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  lastUsedAt: { type: Date, default: Date.now }, // for sessions heavy use tracking
  device: {
    ip: String,
    userAgent: String,
    browser: String,
    os: String,
    raw: mongoose.Schema.Types.Mixed
  },
  geo: { type: mongoose.Schema.Types.Mixed }, // optional geo info from IP lookup
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'UserCredential' }, // admin or system id
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'UserCredential' }
}, { _id: false });

  const ProviderSchema = new mongoose.Schema({
  providerName: { type: String, required: true },
  providerId: { type: String, required: true },
  profile: { type: mongoose.Schema.Types.Mixed }
}, { _id: false });


const PermissionSchema = new mongoose.Schema({
  name: { type: String, required: true }, // e.g. "user.read", "user.update"
  grantedAt: { type: Date, default: Date.now },
  grantedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'UserCredential' } // admin who granted
}, { _id: false });



const UserCredentialSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, index: true, sparse: true },
  passwordHash: { type: String },
  firstName: { type: String, index: true },
  lastName: { type: String, index: true },
  avatar: {
  url: { type: String, default: null },        // public (or CDN) URL to image
  key: { type: String, default: null },        // object key in S3 or filename (useful for deletion)
  mimeType: { type: String, default: null },
  size: { type: Number, default: null },
  uploadedAt: { type: Date, default: null }
},
  roles: { type: [String], default: ['user'], index: true }, // e.g. ['user','admin']
  permissions: { type: [PermissionSchema], default: [] },
  isEmailVerified: { type: Boolean, default: false },
  lastLogin: { type: Date },
  failedLoginAttempts: { type: Number, default: 0 },
  lockedUntil: { type: Date, default: null }, // account lockout timestamp
  sessionTokens: { type: [SessionTokenSchema], default: [] },
  refreshTokens: { type: [ // keep for backward compat if needed
    {
      tokenHash: String,
      expiresAt: Date
    }
  ], default: [] },
  providers: { type: [ProviderSchema], default: [] },
  createdAt: { type: Date, default: Date.now },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'UserCredential' },
  updatedAt: { type: Date, default: Date.now },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'UserCredential' },
  metadata: { type: mongoose.Schema.Types.Mixed } // arbitrary metadata
});

// keep updatedAt current
UserCredentialSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// index for fast lookup by tokenId (for token revocation / reuse detection)
UserCredentialSchema.index({ email: 1 });

module.exports = mongoose.model('UserCredential', UserCredentialSchema);