const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const { google } = require("googleapis");

const app = express();
app.use(express.json());
app.use(cors());

require("dotenv").config();
const mysqlConfig = JSON.parse(process.env.MYSQL_CONFIGURATION);
const jwtSecretKey = process.env.JWT_SECRET;

const connection = mysql.createConnection(mysqlConfig);

connection.connect((error) => {
  if (error) {
    console.log("Failed to connect to the database, reason: ", error);
    return;
  }

  console.log("Connected to the database!");
});

const oAuth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.env.REDIRECT_URI
);

oAuth2Client.setCredentials({
  refresh_token: process.env.REFRESH_TOKEN,
});

async function setupTransporter() {
  const accessToken = await oAuth2Client.getAccessToken();

  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      type: "OAuth2",
      user: process.env.EMAIL_USERNAME,
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      refreshToken: process.env.REFRESH_TOKEN,
      accessToken: accessToken.token,
    },
  });
}

app.post("/api/register", (req, res) => {
  //   console.log(req.body);

  const { nickname, email, password } = req.body;

  bcrypt.hash(password, 10, (error, hashedPassword) => {
    if (error) {
      console.error("Failed to encrypt password!", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    const query = "INSERT INTO users (nickname, email, password) VALUES (?, ?, ?)";
    const values = [nickname, email, hashedPassword];

    connection.query(query, values, (error, result) => {
      if (error) {
        if (error.code === "ER_DUP_ENTRY") {
          return res.status(409).json({ error: "User already exists" });
        } else {
          console.error("Failed to create new user", error);
          return res.status(500).json({ error: "Internal Server Error" });
        }
      }

      // console.log(result);
      res.status(200).json({ message: "New user registered!" });
    });
  });
});

app.post("/api/login", (req, res) => {
  // console.log(req.body);

  const { username, password } = req.body;

  const query = "SELECT id, nickname, password FROM users WHERE email = ?;";
  const values = [username];

  connection.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to login", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: "User does not exist" });
    }

    const { id, nickname, password: hashedPassword } = results[0];

    bcrypt.compare(password, hashedPassword, (error, isMatch) => {
      if (error) {
        console.error("Failed to login:", err);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      if (!isMatch) {
        return res.status(401).json({ error: "Wrong email or password!" });
      }

      const token = jwt.sign({ username }, jwtSecretKey, {
        expiresIn: "1h",
      });

      res.status(200).json({ id, nickname, username, token });
    });
  });
});

app.post("/api/forgot-password", (req, res) => {
  // console.log(req.body);

  const { email } = req.body;

  const query = "SELECT id FROM users WHERE email = ?;";
  const values = [email];

  connection.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to find user", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: "User not found" });
    }

    const token = jwt.sign({ email }, jwtSecretKey, { expiresIn: "15m" });
    const expiration = new Date(Date.now() + 900000);

    const tokenQuery =
      "UPDATE users SET reset_token = ?, reset_token_expiration = ? WHERE email = ?;";
    const tokenValues = [token, expiration, email];

    connection.query(tokenQuery, tokenValues, (error, result) => {
      if (error) {
        console.error("Failed to update token in database", error);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      const mailOptions = {
        from: process.env.EMAIL_USERNAME,
        to: email,
        subject: "Password Reset",
        text: `Click the link to reset your password: http://localhost:3000/reset-password/${token}`,
      };

      setupTransporter().then((transporter) => {
        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error("Failed to send email", error);
            return res.status(500).json({ error: "Internal Server Error" });
          }

          res.status(200).json({ message: "Password reset email sent!" });
        });
      });
    });
  });
});

app.get("/api/validate-token", (req, res) => {
  const { token } = req.query;

  try {
    jwt.verify(token, jwtSecretKey);

    const query =
      "SELECT * FROM users WHERE reset_token = ? AND reset_token_expiration > NOW();";
    const values = [token];

    connection.query(query, values, (error, results) => {
      if (error) {
        console.error("Failed to validate token", error);

        return res.status(500).json({ error: "Internal Server Error" });
      }

      if (results.length === 0) {
        return res.status(401).json({ error: "Invalid or expired token" });
      }

      res.status(200).json({ message: "Token is valid" });
    });
  } catch (error) {
    console.error("Failed to verify token", error);

    return res.status(401).json({ error: "Invalid or expired token" });
  }
});

app.post("/api/reset-password", (req, res) => {
  // console.log("req.body", req.body);

  const { token, newPassword } = req.body;

  try {
    const decoded = jwt.verify(token, jwtSecretKey);
    const email = decoded.email;

    bcrypt.hash(newPassword, 10, (error, hashedPassword) => {
      if (error) {
        console.error("Failed to encrypt password", error);

        return res.status(500).json({ error: "Internal Server Error" });
      }

      const query =
        "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiration = NULL WHERE email = ?;";
      const values = [hashedPassword, email];

      connection.query(query, values, (error, result) => {
        if (error) {
          console.error("Failed to update password", error);

          return res.status(500).json({ error: "Internal Server Error" });
        }

        res.status(200).json({ message: "Password updated successfully!" });
      });
    });
  } catch (error) {
    console.error("Failed to verify token", error);

    return res.status(401).json({ error: "Invalid or expired token" });
  }
});

const authMiddleware = (req, res, next) => {
  const token = req.headers.token;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, jwtSecretKey);

    next();
  } catch (error) {
    console.error("Failed to verify token", error);

    return res.status(401).json({ error: "Unauthorized" });
  }
};

app.post("/api/account-books", authMiddleware, (req, res) => {
  const { id, name, tag, description } = req.body;

  const query =
    "INSERT INTO account_books (user_id, name, tag, description) VALUES (?, ?, ?, ?)";
  const values = [id, name, tag, description];

  connection.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to create new account book", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // console.log(result);
    res.status(200).json({ message: "New accound book created!" });
  });
});

app.put("/api/account-books", authMiddleware, (req, res) => {
  console.log("req.body", req.body);
  const { accountBookId, userId, name, tag, description } = req.body;

  const query =
    "UPDATE account_books SET user_id = ?, name = ?, tag = ?, description = ? WHERE id = ?;";
  const values = [userId, name, tag, description, accountBookId];

  connection.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to update account book", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    console.log(results);

    res.status(200).json({ message: "Accound book updated!" });
  });
});

app.get("/api/account-books", authMiddleware, (req, res) => {
  const { id } = req.headers;
  console.log("id", id);

  const query = "SELECT * FROM account_books WHERE user_id = ?;";
  const values = [id];

  connection.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to get account books", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // console.log("results", results);
    res.status(200).json({ accountBookList: results });
  });
});

app.delete("/api/account-books", authMiddleware, (req, res) => {
  const id = req.headers.accountbookid;
  console.log("id", id);
  const query = "DELETE FROM account_books WHERE id = ?;";
  const values = [id];

  connection.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to delete account book", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    console.log(results);
    res.status(200).json({ message: "Deleted" });
  });
});

app.listen(6789, () => {
  console.log("Server Listening on Port 6789...");
});
