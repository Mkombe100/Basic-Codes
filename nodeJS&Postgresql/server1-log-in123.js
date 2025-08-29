const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const path = require("path");
const session = require("express-session");

const app = express();

const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "login123",
  password: "@Mkombe566",  // change if needed
  port: 5432,
});

app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "secret_key",
    resave: false,
    saveUninitialized: false,
  })
);

// Protect dashboard
function checkAuth(req, res, next) {
  if (req.session.email) {
    next();
  } else {
    res.redirect("/");
  }
}

// Routes
app.get("/", (req, res) => {
  if (req.session.email) return res.redirect("/dashboard");
  res.render("index", { message: null });
});

// Register
app.post("/register", async (req, res) => {
  const { first_name, middle_name, last_name, email, contact_info, address, age, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO instructor (first_name, middle_name, last_name, email, contact_info, address, age, password) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
      [first_name, middle_name, last_name, email, contact_info, address, age, hashedPassword]
    );
    res.render("index", { message: "You are successfully registered!" });
  } catch (error) {
    console.error(error);
    res.render("index", { message: "Error: " + error.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM instructor WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.render("index", { message: "Email not found!" });

    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.render("index", { message: "Invalid password!" });

    req.session.email = user.email;
    res.redirect("/dashboard");
  } catch (error) {
    console.error(error);
    res.render("index", { message: "Error: " + error.message });
  }
});

// Dashboard
app.get("/dashboard", checkAuth, (req, res) => {
  res.render("dashboard", { email: req.session.email });
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.redirect("/dashboard");
    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

app.listen(3000, () => console.log("✅ Server running on http://localhost:3000"));
