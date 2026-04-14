import { User } from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// Register User
export const register = async (req, res) => {
  try {
    const { fullName, username, password, confirmPassword, gender, profilePhoto } = req.body;
    if (!fullName || !username || !password || !confirmPassword || !gender) {
      return res.status(400).json({ message: "All fields are required" });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }
    const user = await User.findOne({ username });
    if (user) {
      return res.status(400).json({ message: "Username already exists" });
    }

    // Hashed Password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Profile Photo
    const maleProfilePhoto = `https://api.dicebear.com/9.x/adventurer/svg?seed=${encodeURIComponent(username)}`;
    const femaleProfilePhoto = `https://api.dicebear.com/9.x/lorelei/svg?seed=${encodeURIComponent(username)}`;

    const finalProfilePhoto = profilePhoto ? profilePhoto : (gender === "male" ? maleProfilePhoto : femaleProfilePhoto);

    await User.create({
      fullName,
      username,
      password: hashedPassword,
      gender,
      profilePhoto: finalProfilePhoto,
    });
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error registering user" });
  }
};

// Login User
export const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: "Invalid username or password" });
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(400).json({ message: "Invalid username or password" });
    }
    const tokenData = {
      userId: user._id,
    };

    const token = await jwt.sign(tokenData, process.env.JWT_SECRET_KEY, {
      expiresIn: "1d",
    });
    res
      .status(200)
      .cookie("token", token, {
        maxAge: 24 * 60 * 60 * 1000, // 1 day
        httpOnly: true,
        sameSite: "strict",
      })
      .json({
        _id: user._id,
        fullName: user.fullName,
        username: user.username,
        profilePhoto: user.profilePhoto,
      });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error logging in user" });
  }
};

// Logout User
export const logout = (req, res) => {
  try {
    return res
      .status(200)
      .cookie("token", "", { maxAge: 0 })
      .json({ message: "User logged out successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error logging out user" });
  }
};

// Get User Profile
export const getOtherUsers = async (req, res) => {
  try {
    const loggedInUserId = req.id;
    const otherUsers = await User.find({
      _id: { $ne: loggedInUserId },
    }).select("-password");
    res.status(200).json({ users: otherUsers });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error fetching other users" });
  }
};

// Update User Profile
export const updateProfile = async (req, res) => {
  try {
    const loggedInUserId = req.id;
    const { fullName, profilePhoto } = req.body;

    const user = await User.findById(loggedInUserId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (fullName) user.fullName = fullName;
    if (profilePhoto) user.profilePhoto = profilePhoto;

    await user.save();

    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      username: user.username,
      profilePhoto: user.profilePhoto,
      message: "Profile updated successfully",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error updating profile" });
  }
};
