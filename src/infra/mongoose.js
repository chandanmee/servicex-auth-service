const mongoose = require('mongoose');

async function connectMongo(uri) {
  mongoose.set('strictQuery', true);
  mongoose.set('autoIndex', false);
  await mongoose.connect(uri);
  console.log("📦 MongoDB connected");
}

module.exports = { connectMongo };
