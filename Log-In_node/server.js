const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const pool = new Pool({
  user: "postgres",      // change if needed
  host: "localhost",
  database: "auth_demo", // database name
  password: "yourpassword", // your postgres password
  port: 5432,
});

app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Home (Login/Register page)
app.get("/", (req, res) => {
  res.render("index", { message: null });
});

// Handle login/register
app.post("/", async (req, res) => {
  const { username, password, action } = req.body;

  try {
    if (action === "register") {
      const hashedPassword = await bcrypt.hash(password, 10);

      await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
        username,
        hashedPassword,
      ]);

      return res.render("index", { message: " Registration successful! Please login." });
    } else if (action === "login") {
      const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
      if (result.rows.length === 0) {
        return res.render("index", { message: "User not found!" });
      }

      const user = result.rows[0];
      const isValid = await bcrypt.compare(password, user.password);

      if (!isValid) {
        return res.render("index", { message: " Invalid password!" });
      }

      return res.render("dashboard", { username: user.username });
    }
  } catch (err) {
    console.error(err);
    res.render("index", { message: " Error: " + err.message });
  }
});

// Dashboard
app.get("/dashboard", (req, res) => {
  res.render("dashboard", { username: "Guest" });
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));                                         
