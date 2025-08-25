const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const session = require("express-session");
const path = require("path");

const app = express();
const db = new sqlite3.Database("./database.sqlite");

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({
    secret: "mysecretkey",
    resave: false,
    saveUninitialized: false,
  })
);

// Create users table if not exists
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)`);

// Serve frontend
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Register route
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  db.run(
    `INSERT INTO users (username, password) VALUES (?, ?)`,
    [username, hashed],
    (err) => {
      if (err) return res.send("User already exists");
      res.redirect("/");
    }
  );
});

// Login route
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user) return res.send("Invalid username or password");
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.send("Invalid username or password");

    req.session.user = user;
    res.send("Login successful! Welcome " + username);
  });
});

app.listen(3000, () => console.log("Server running at http://localhost:3000"));
