const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const app = express();

const jsonServerRouter = jsonServer.router(path.join(__dirname, "db.json"));
const port = process.env.PORT || 80;

const privateKey = fs.readFileSync("private.key", "utf-8");

app.use(bodyParser.json());
app.use(cors());

// Authentication middleware
function authenticate(req, res, next) {
  const { username, password } = req.body;
  const users = getUsersFromDb();

  const user = users.find(
    (u) => u.username === username && bcrypt.compareSync(password, u.password)
  );

  if (user) {
    next();
  } else {
    res.status(401).json({ message: "Authentication failed" });
  }
}

// Read user data from db.json
function getUsersFromDb() {
  const dbData = fs.readFileSync(path.join(__dirname, "db.json"), "utf8");
  return JSON.parse(dbData).users || [];
}

// Write user data to db.json
function writeUsersToDb(users) {
  const dbData = { users };
  fs.writeFileSync(
    path.join(__dirname, "db.json"),
    JSON.stringify(dbData, null, 2)
  );
}
app.get("/", authenticate, (req, res) => {
  
  res.json("deployed successfully");
});
// Route for user login
app.post("/login", authenticate, (req, res) => {
  const token = jwt.sign({ username: req.body.username }, privateKey, {
    algorithm: "RS256",
    expiresIn: 60,
  });
  res.json({ token });
});

// Route for user registration (sign up)
app.post("/register", (req, res) => {
  const { username, email, password } = req.body;
  const users = getUsersFromDb();

  // Check if the username is already in use
  if (users.some((u) => u.username === username)) {
    res.status(400).json({ message: "Username already in use" });
    return;
  }

  // Hash the password before storing it
  const hashedPassword = bcrypt.hashSync(password, 10);

  // Add the new user to the array
  users.push({ username, email, password: hashedPassword });

  // Update the user data in the db.json file
  writeUsersToDb(users);

  res.status(201).json({ message: "User registered successfully" });
});

// Use JSON Server for user management endpoints
app.use("/users", jsonServerRouter);

app.listen(port, () => {
  console.log(`Server is not running on http://localhost:${port}`);
});
