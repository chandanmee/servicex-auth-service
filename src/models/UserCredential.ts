import mongoose from "mongoose";

const RefreshTokenSchema = new mongoose.Schema(
  {
    tokenHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true }
  },
  { _id: false }
);

const SessionTokenSchema = new mongoose.Schema(
  {
    tokenId: { type: String, required: true },
    tokenHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true },
    lastUsedAt: { type: Date, default: Date.now },
    device: {
      ip: String,
      userAgent: String,
      browser: String,
      os: String,
      raw: mongoose.Schema.Types.Mixed
    },
    geo: { type: mongoose.Schema.Types.Mixed },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "UserCredential" },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "UserCredential" }
  },
  { _id: false }
);

const ProviderSchema = new mongoose.Schema(
  {
    providerName: { type: String, required: true },
    providerId: { type: String, required: true },
    profile: { type: mongoose.Schema.Types.Mixed }
  },
  { _id: false }
);

const PermissionSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    grantedAt: { type: Date, default: Date.now },
    grantedBy: { type: mongoose.Schema.Types.ObjectId, ref: "UserCredential" }
  },
  { _id: false }
);

const UserCredentialSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, index: true, sparse: true },
  passwordHash: { type: String },
  firstName: { type: String, index: true },
  lastName: { type: String, index: true },
  avatar: {
    url: { type: String, default: null },
    key: { type: String, default: null },
    mimeType: { type: String, default: null },
    size: { type: Number, default: null },
    uploadedAt: { type: Date, default: null }
  },
  roles: { type: [String], default: ["user"], index: true },
  permissions: { type: [PermissionSchema], default: [] },
  isEmailVerified: { type: Boolean, default: false },
  lastLogin: { type: Date },
  failedLoginAttempts: { type: Number, default: 0 },
  lockedUntil: { type: Date, default: null },
  sessionTokens: { type: [SessionTokenSchema], default: [] },
  refreshTokens: { type: [{ tokenHash: String, expiresAt: Date }], default: [] },
  providers: { type: [ProviderSchema], default: [] },
  createdAt: { type: Date, default: Date.now },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "UserCredential" },
  updatedAt: { type: Date, default: Date.now },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "UserCredential" },
  metadata: { type: mongoose.Schema.Types.Mixed }
});

UserCredentialSchema.pre("save", function (next) {
  (this as any).updatedAt = Date.now();
  next();
});

UserCredentialSchema.index({ email: 1 });

const User = mongoose.model("UserCredential", UserCredentialSchema);
export default User;
