import mongoose from "mongoose";

export async function connectMongo(uri: string) {
  mongoose.set("strictQuery", true);
  mongoose.set("autoIndex", false);
  await mongoose.connect(uri);
  console.log("📦 MongoDB connected");
}
