import { Server } from "socket.io";
import http from "http";
import express from "express";

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

export const getReceiverSocketId = (receiverId) => {
  return userSocketMap[receiverId];
}

import { User } from "../models/userModel.js";

const userSocketMap = {};

io.on("connection", async (socket) => {
  console.log("a user connected");

  const userId = socket.handshake.query.userId;
  if (userId !== undefined) {
    userSocketMap[userId] = socket.id;
    // Optionally update lastSeen to 'online' state or just leave it
  }

  io.emit("getOnlineUsers", Object.keys(userSocketMap));

  socket.on("disconnect", async () => {
    console.log("user disconnected", socket.id);
    if (userId) {
      delete userSocketMap[userId];
      try {
        await User.findByIdAndUpdate(userId, { lastSeen: Date.now() });
      } catch (error) {
        console.error("Error updating lastSeen on disconnect:", error);
      }
    }
    io.emit("getOnlineUsers", Object.keys(userSocketMap));
  });
});

export { app, io, server };
