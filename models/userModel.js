import mongoose from "mongoose";

const userModel = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
  },
  profilePhoto: {
    type: String,
    default: "",
  },
  gender: {
    type: String,
    required: true,
    enum: ["male", "female", "other"],
  },
  lastSeen: {
    type: Date,
    default: Date.now,
  },
},{timestamps: true});

export const User = mongoose.model("User", userModel);
