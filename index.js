// const express = require("express");
// const http = require("http");
// const cors = require("cors");
// const jwt = require("jsonwebtoken");
// const bcrypt = require("bcryptjs");
// const { Server } = require("socket.io");

// const app = express();
// app.use(express.json());
// app.use(cors());

// const JWT_SECRET = "SECRET123";   // change in production

// // Dummy in-memory users
// let users = [];

// // ----------------------------
// // SIGNUP
// // ----------------------------
// app.post("/signup", async (req, res) => {
//   const { name, email, password } = req.body;

//   const exists = users.find((u) => u.email === email);
//   if (exists) return res.json({ error: "User already exists" });

//   const hashed = await bcrypt.hash(password, 10);

//   const newUser = { id: Date.now(), name, email, password: hashed };
//   users.push(newUser);

//   return res.json({ message: "Signup successful" });
// });

// // ----------------------------
// // LOGIN
// // ----------------------------
// app.post("/signin", async (req, res) => {
//   const { email, password } = req.body;

//   const user = users.find((u) => u.email === email);
//   if (!user) return res.json({ error: "Invalid email" });

//   const match = await bcrypt.compare(password, user.password);
//   if (!match) return res.json({ error: "Incorrect password" });

//   const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);

//   return res.json({ message: "Signin successful", token });
// });

// // ----------------------------
// // AUTH MIDDLEWARE
// // ----------------------------
// function auth(req, res, next) {
//   const token = req.headers["authorization"];

//   if (!token) return res.json({ error: "No token" });

//   try {
//     const decoded = jwt.verify(token.split(" ")[1], JWT_SECRET);
//     req.user = decoded;
//     next();
//   } catch (err) {
//     return res.json({ error: "Invalid token" });
//   }
// }

// // ----------------------------
// // PROTECTED API
// // ----------------------------
// app.get("/me", auth, (req, res) => {
//   const user = users.find((u) => u.id === req.user.id);
//   res.json({ id: user.id, name: user.name, email: user.email });
// });

// // ----------------------------
// // SOCKET.IO CHAT
// // ----------------------------
// const server = http.createServer(app);

// const io = new Server(server, {
//   cors: { origin: "*" },
// });

// io.on("connection", (socket) => {
//   console.log("User connected:", socket.id);

//   socket.on("sendMessage", (data) => {
//     io.emit("receiveMessage", data); // broadcast
//   });
// });

// server.listen(5000, () => console.log("Server running on 5000"));



// upar wala basic code 

// ---------------------------------------------------------------------


// server/index.js
// require("dotenv").config();
// const express = require("express");
// const http = require("http");
// const cors = require("cors");
// const mongoose = require("mongoose");
// const jwt = require("jsonwebtoken");
// const bcrypt = require("bcryptjs");
// const multer = require("multer");
// const path = require("path");
// const fs = require("fs");
// const { Server } = require("socket.io");

// const app = express();
// app.use(cors());
// app.use(express.json());
// app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
// const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/messenger_app";

// // ----------------- Mongoose Schemas -----------------
// mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// const userSchema = new mongoose.Schema({
//   name: String,
//   email: { type: String, unique: true },
//   password: String,
//   online: { type: Boolean, default: false },
//   socketId: { type: String, default: null },
// });

// const chatSchema = new mongoose.Schema({
//   type: { type: String, enum: ["private", "group"], default: "private" },
//   name: String, // group name
//   members: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
//   createdAt: { type: Date, default: Date.now },
// });

// const messageSchema = new mongoose.Schema({
//   chat: { type: mongoose.Schema.Types.ObjectId, ref: "Chat" },
//   sender: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
//   text: String,
//   image: String, // image path/url
//   readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
//   createdAt: { type: Date, default: Date.now },
// });

// const User = mongoose.model("User", userSchema);
// const Chat = mongoose.model("Chat", chatSchema);
// const Message = mongoose.model("Message", messageSchema);

// // ----------------- Multer for image uploads -----------------
// const uploadDir = path.join(__dirname, "uploads");
// if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// const storage = multer.diskStorage({
//   destination: (req, file, cb) => cb(null, uploadDir),
//   filename: (req, file, cb) =>
//     cb(null, Date.now() + "_" + file.originalname.replace(/\s+/g, "_")),
// });
// const upload = multer({ storage });

// // ----------------- Auth helpers -----------------
// function generateToken(user) {
//   return jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
// }
// async function authMiddleware(req, res, next) {
//   const header = req.headers["authorization"];
//   if (!header) return res.status(401).json({ error: "No token" });
//   const token = header.split(" ")[1];
//   try {
//     const decoded = jwt.verify(token, JWT_SECRET);
//     req.user = await User.findById(decoded.id);
//     if (!req.user) return res.status(401).json({ error: "User not found" });
//     next();
//   } catch (err) {
//     return res.status(401).json({ error: "Invalid token" });
//   }
// }

// // ----------------- Routes -----------------

// // Signup
// app.post("/signup", async (req, res) => {
//   const { name, email, password } = req.body;
//   try {
//     if (!name || !email || !password) return res.status(400).json({ error: "Missing fields" });
//     const exists = await User.findOne({ email });
//     if (exists) return res.status(400).json({ error: "User already exists" });
//     const hashed = await bcrypt.hash(password, 10);
//     const u = new User({ name, email, password: hashed });
//     await u.save();
//     return res.json({ message: "Signup successful" });
//   } catch (err) {
//     return res.status(500).json({ error: err.message });
//   }
// });

// // Signin
// app.post("/signin", async (req, res) => {
//   const { email, password } = req.body;
//   try {
//     const u = await User.findOne({ email });
//     if (!u) return res.status(400).json({ error: "Invalid email or password" });
//     const ok = await bcrypt.compare(password, u.password);
//     if (!ok) return res.status(400).json({ error: "Invalid email or password" });
//     const token = generateToken(u);
//     return res.json({ token });
//   } catch (err) {
//     return res.status(500).json({ error: err.message });
//   }
// });

// // Get current user
// app.get("/me", authMiddleware, async (req, res) => {
//   const u = req.user;
//   res.json({ id: u._id, name: u.name, email: u.email, online: u.online });
// });

// // Create chat (private or group)
// // For private chat, pass { type: 'private', memberId: otherUserId }
// // For group, pass { type: 'group', name, members: [id1,id2,...] }
// app.post("/chats", authMiddleware, async (req, res) => {
//   const { type, name, members, memberId } = req.body;
//   try {
//     if (type === "private") {
//       // ensure consistent ordering of members to avoid duplicate private chats
//       const m1 = req.user._id;
//       const m2 = memberId;
//       if (!m2) return res.status(400).json({ error: "memberId required for private chat" });

//       // Check existing private chat with same two members
//       const existing = await Chat.findOne({
//         type: "private",
//         members: { $all: [m1, m2], $size: 2 },
//       });
//       if (existing) return res.json(existing);
//       const chat = new Chat({ type: "private", members: [m1, m2] });
//       await chat.save();
//       return res.json(chat);
//     } else {
//       // group
//       if (!members || !Array.isArray(members) || members.length < 1)
//         return res.status(400).json({ error: "members required for group chat" });
//       const chat = new Chat({ type: "group", name: name || "Group", members: [req.user._id, ...members] });
//       await chat.save();
//       return res.json(chat);
//     }
//   } catch (err) {
//     return res.status(500).json({ error: err.message });
//   }
// });

// // Get user's chats
// app.get("/chats", authMiddleware, async (req, res) => {
//   const chats = await Chat.find({ members: req.user._id }).populate("members", "name email online");
//   res.json(chats);
// });

// // Get messages for a chat (paginated)
// app.get("/chats/:chatId/messages", authMiddleware, async (req, res) => {
//   const { chatId } = req.params;
//   const { before, limit = 50 } = req.query; // before = ISO date or message id (not implemented advanced)
//   const messages = await Message.find({ chat: chatId })
//     .sort({ createdAt: -1 })
//     .limit(parseInt(limit))
//     .populate("sender", "name email")
//     .lean();
//   res.json(messages.reverse()); // return oldest -> newest
// });

// // Upload image
// app.post("/upload", authMiddleware, upload.single("image"), async (req, res) => {
//   if (!req.file) return res.status(400).json({ error: "No file" });
//   const url = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
//   res.json({ url });
// });

// // ----------------- Socket.IO -----------------
// const server = http.createServer(app);
// const io = new Server(server, {
//   cors: { origin: "*" },
// });

// io.use(async (socket, next) => {
//   // Expect token in socket.handshake.auth.token
//   try {
//     const token = socket.handshake.auth?.token;
//     if (!token) return next(new Error("No token"));
//     const decoded = jwt.verify(token.split(" ")[1] || token, JWT_SECRET);
//     const user = await User.findById(decoded.id);
//     if (!user) return next(new Error("User not found"));
//     socket.user = user;
//     next();
//   } catch (err) {
//     next(new Error("Authentication error"));
//   }
// });

// io.on("connection", async (socket) => {
//   const user = socket.user;
//   // mark online
//   await User.findByIdAndUpdate(user._id, { online: true, socketId: socket.id });
//   // broadcast user online
//   io.emit("userOnline", { userId: user._id, online: true });

//   console.log("socket connected:", user.name, socket.id);

//   // join personal room for private messages and allow joining chat rooms from client
//   socket.join(String(user._id));

//   // client asks to join a chat room (private or group)
//   socket.on("joinChat", (chatId) => {
//     socket.join(chatId);
//   });

//   // typing indicator
//   socket.on("typing", ({ chatId, isTyping }) => {
//     socket.to(chatId).emit("typing", { chatId, userId: user._id, isTyping });
//   });

//   // send message (via socket) -> save to DB and broadcast to chat room
//   // data: { chatId, text, image }
//   socket.on("sendMessage", async (data, cb) => {
//     try {
//       const { chatId, text, image } = data;
//       if (!chatId) return;
//       const msg = new Message({
//         chat: chatId,
//         sender: user._id,
//         text: text || "",
//         image: image || null,
//         readBy: [user._id],
//       });
//       await msg.save();
//       const populated = await msg.populate("sender", "name email").execPopulate();
//       io.to(chatId).emit("newMessage", populated);
//       // Optionally notify offline users (push notifications) — not implemented
//       if (cb) cb({ ok: true });
//     } catch (err) {
//       if (cb) cb({ ok: false, error: err.message });
//     }
//   });

//   // mark messages read
//   socket.on("markRead", async ({ chatId }) => {
//     await Message.updateMany({ chat: chatId, readBy: { $ne: user._id } }, { $push: { readBy: user._id } });
//     io.to(chatId).emit("messagesRead", { chatId, userId: user._id });
//   });

//   socket.on("disconnect", async () => {
//     await User.findByIdAndUpdate(user._id, { online: false, socketId: null });
//     io.emit("userOnline", { userId: user._id, online: false });
//     console.log("socket disconnected:", user.name);
//   });
// });
// //-------------------------------------
// // resolve email -> user id
// app.get("/users/by-email", authMiddleware, async (req, res) => {
//   const email = req.query.email;
//   if (!email) return res.status(400).json({ error: "email required" });
//   const u = await User.findOne({ email }, "_id name email");
//   if (!u) return res.status(404).json({ error: "Not found" });
//   res.json({ id: u._id, name: u.name, email: u.email });
// });

// // resolve multiple emails to ids (for group creation)
// app.post("/resolve-emails", authMiddleware, async (req, res) => {
//   const { emails } = req.body;
//   if (!emails || !Array.isArray(emails)) return res.status(400).json({ error: "emails required" });
//   const users = await User.find({ email: { $in: emails } }, "_id email");
//   const ids = users.map((u) => u._id);
//   res.json({ ids });
// });







// // ----------------- Start server -----------------
// const PORT = process.env.PORT || 5000;
// server.listen(PORT, () => console.log("Server running on port", PORT));





// -----------------------------------------------------this is updated------------------------



// ==========================
//       SETUP
// ==========================
require("dotenv").config();
const express = require("express");
const http = require("http");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { Server } = require("socket.io");

const app = express();
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/messenger";

// ==========================
//     MONGOOSE MODELS
// ==========================
mongoose.connect(MONGO_URI);

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  online: { type: Boolean, default: false },
  socketId: String,
});

const chatSchema = new mongoose.Schema({
  type: { type: String, enum: ["private", "group"], default: "private" },
  name: String,
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  createdAt: { type: Date, default: Date.now },
});

const messageSchema = new mongoose.Schema({
  chat: { type: mongoose.Schema.Types.ObjectId, ref: "Chat" },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  text: String,
  image: String,
  readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Chat = mongoose.model("Chat", chatSchema);
const Message = mongoose.model("Message", messageSchema);

// ==========================
//        IMAGE UPLOAD
// ==========================
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});
const upload = multer({ storage });

// ==========================
//     AUTH HELPERS
// ==========================
function generateToken(user) {
  return jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: "No token" });

    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = await User.findById(decoded.id);
    if (!req.user) return res.status(401).json({ error: "User not found" });

    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ==========================
//        AUTH ROUTES
// ==========================
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  const exists = await User.findOne({ email });
  if (exists) return res.status(400).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ name, email, password: hashed });
  await user.save();

  res.json({ message: "Signup successful" });
});

app.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  const u = await User.findOne({ email });
  if (!u) return res.status(400).json({ error: "Invalid email or password" });

  const ok = await bcrypt.compare(password, u.password);
  if (!ok) return res.status(400).json({ error: "Invalid email or password" });

  const token = generateToken(u);
  res.json({ token });
});

app.get("/me", auth, (req, res) => {
  res.json({ id: req.user._id, name: req.user.name, email: req.user.email, online: req.user.online });
});

// ==========================
//         CHAT ROUTES
// ==========================
app.post("/chats", auth, async (req, res) => {
  const { type, memberId, name, members } = req.body;

  if (type === "private") {
    const existing = await Chat.findOne({
      type: "private",
      members: { $all: [req.user._id, memberId], $size: 2 },
    });
    if (existing) return res.json(existing);

    const chat = await Chat.create({
      type: "private",
      members: [req.user._id, memberId],
    });

    return res.json(chat);
  }

  // group
  const chat = await Chat.create({
    type: "group",
    name,
    members: [req.user._id, ...members],
  });

  res.json(chat);
});

app.get("/chats", auth, async (req, res) => {
  const chats = await Chat.find({ members: req.user._id })
    .populate("members", "name email online");

  res.json(chats);
});

app.get("/chats/:id/messages", auth, async (req, res) => {
  const messages = await Message.find({ chat: req.params.id })
    .sort({ createdAt: 1 })
    .populate("sender", "name email");

  res.json(messages);
});

// ==========================
//     IMAGE UPLOAD ROUTE
// ==========================
app.post("/upload", auth, upload.single("image"), (req, res) => {
  const url = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
  res.json({ url });
});

// ==========================
//        SOCKET.IO
// ==========================
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" },
});

// Authenticate socket user
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    const decoded = jwt.verify(token.split(" ")[1] || token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    socket.user = user;
    next();
  } catch {
    next(new Error("Socket Auth Failed"));
  }
});

io.on("connection", async (socket) => {
  const user = socket.user;
  console.log(`Connected: ${user.name}`);

  await User.findByIdAndUpdate(user._id, { online: true, socketId: socket.id });
  io.emit("userOnline", { userId: user._id, online: true });

  socket.join(String(user._id));

  socket.on("joinChat", (chatId) => socket.join(chatId));

  socket.on("typing", ({ chatId, isTyping }) => {
    socket.to(chatId).emit("typing", { chatId, userId: user._id, isTyping });
  });

  socket.on("sendMessage", async (data, cb) => {
    try {
      const msg = await Message.create({
        chat: data.chatId,
        sender: user._id,
        text: data.text || "",
        image: data.image || null,
        readBy: [user._id],
      });

      const populated = await Message.findById(msg._id).populate("sender", "name email");

      io.to(data.chatId).emit("newMessage", populated);

      cb?.({ ok: true });
    } catch (e) {
      cb?.({ ok: false, error: e.message });
    }
  });

  socket.on("disconnect", async () => {
    await User.findByIdAndUpdate(user._id, { online: false, socketId: null });
    io.emit("userOnline", { userId: user._id, online: false });
    console.log(`Disconnected: ${user.name}`);
  });
});

// ==========================
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log("Server running on", PORT));
