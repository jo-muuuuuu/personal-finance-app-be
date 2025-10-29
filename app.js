const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");

const app = express();
app.use(express.json());
app.use(cors());

app.use("/api/uploads", express.static(path.join(__dirname, "uploads")));
const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

require("dotenv").config();
const mysqlConfig = JSON.parse(process.env.MYSQL_CONFIGURATION);
const jwtSecretKey = process.env.JWT_SECRET;

const pool = mysql.createPool(mysqlConfig);

pool.getConnection((error, connection) => {
  if (error) {
    console.log("Failed to connect to the database, reason: ", error);
    return;
  }

  console.log("Connected to the database!");
  connection.release();
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

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD,
  },
});

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

    pool.query(query, values, (error, result) => {
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

  const query = "SELECT id, nickname, password, avatar_url FROM users WHERE email = ?;";
  const values = [username];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to login", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: "User does not exist" });
    }

    const { id, nickname, password: hashedPassword, avatar_url: avatarURL } = results[0];

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

      res.status(200).json({ id, nickname, username, avatarURL, token });
    });
  });
});

app.post("/api/forgot-password", (req, res) => {
  // console.log(req.body);

  const { email } = req.body;

  const query = "SELECT id FROM users WHERE email = ?;";
  const values = [email];

  pool.query(query, values, (error, results) => {
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

    pool.query(tokenQuery, tokenValues, (error, result) => {
      if (error) {
        console.error("Failed to update token in database", error);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      const mailOptions = {
        from: process.env.EMAIL_USERNAME,
        to: email,
        subject: "Password Reset",
        // text: `Click the link to reset your password: ${process.env.PUBLIC_IP}/reset-password/${token}`,
        text: `Click the link to reset your password: ${process.env.PUBLIC_IP}/reset-password/${token}`,
      };

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

app.get("/api/validate-token", (req, res) => {
  const { token } = req.query;

  try {
    jwt.verify(token, jwtSecretKey);

    const query =
      "SELECT * FROM users WHERE reset_token = ? AND reset_token_expiration > NOW();";
    const values = [token];

    pool.query(query, values, (error, results) => {
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

      pool.query(query, values, (error, result) => {
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

app.post("/api/profile-reset-password", (req, res) => {
  const { token, oldPassword, newPassword } = req.body;

  try {
    const decoded = jwt.verify(token, jwtSecretKey);
    const email = decoded.username;

    const query = "SELECT password FROM users WHERE email = ?;";
    const values = [email];

    pool.query(query, values, (error, results) => {
      if (error) {
        console.error("Database query error:", error);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      if (results.length === 0) {
        return res.status(401).json({ error: "User does not exist" });
      }

      const { password: hashedPassword } = results[0];

      bcrypt.compare(oldPassword, hashedPassword, (compareError, isMatch) => {
        if (compareError) {
          console.error("Password comparison error:", compareError);
          return res.status(500).json({ error: "Internal Server Error" });
        }

        if (!isMatch) {
          return res.status(401).json({ error: "Incorrect old password!" });
        }

        // Old password is correct, proceed to hash the new password
        bcrypt.hash(newPassword, 10, (hashError, newHashedPassword) => {
          if (hashError) {
            console.error("Password hashing error:", hashError);
            return res.status(500).json({ error: "Internal Server Error" });
          }

          const updateQuery =
            "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiration = NULL WHERE email = ?;";
          const updateValues = [newHashedPassword, email];

          pool.query(updateQuery, updateValues, (updateError, result) => {
            if (updateError) {
              console.error("Password update error:", updateError);
              return res.status(500).json({ error: "Internal Server Error" });
            }

            res.status(200).json({ message: "Password updated successfully!" });
          });
        });
      });
    });
  } catch (error) {
    console.error("Token verification error:", error);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
});

app.post("/api/upload-avatar", authMiddleware, upload.single("image"), (req, res) => {
  try {
    const { email } = req.headers;
    const avatarPath = `/uploads/${req.file.filename}`;

    const query = "UPDATE users SET avatar_url = ? WHERE email = ?";
    const values = [avatarPath, email];

    pool.query(query, values, (error, result) => {
      if (error) {
        console.error("Failed to update avatar", error);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      res.status(200).json({
        message: "Avatar uploaded successfully",
        avatarURL: avatarPath,
      });
    });
  } catch (err) {
    console.error("Upload avatar error:", err);
    res.status(500).json({ error: "Failed to upload avatar" });
  }
});

app.post("/api/account-books", authMiddleware, (req, res) => {
  const { userId, name, tag, description } = req.body;

  const query =
    "INSERT INTO account_books (user_id, name, tag, description) VALUES (?, ?, ?, ?)";
  const values = [userId, name, tag, description];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to create new account book", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // console.log(result);
    res.status(200).json({ message: "New accound book created!" });
  });
});

app.put("/api/account-books/:id", authMiddleware, (req, res) => {
  // console.log("req.body", req.body);
  const { userId, name, tag, description } = req.body;
  const accountBookId = req.params.id;

  const query =
    "UPDATE account_books SET user_id = ?, name = ?, tag = ?, description = ? WHERE id = ?;";
  const values = [userId, name, tag, description, accountBookId];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to update account book", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // console.log(results);

    res.status(200).json({ message: "Accound book updated!" });
  });
});

app.get("/api/account-books", authMiddleware, (req, res) => {
  const { id } = req.headers;
  // console.log("id", id);

  const query = "SELECT * FROM account_books WHERE user_id = ? ORDER BY created_at DESC;";
  const values = [id];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to get account books", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // console.log("results", results);
    res.status(200).json({ accountBookList: results });
  });
});

app.delete("/api/account-books/:id", authMiddleware, (req, res) => {
  const accountBookId = req.params.id;
  // console.log("id", id);
  const query = "DELETE FROM account_books WHERE id = ?;";
  const values = [accountBookId];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to delete account book", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // console.log(results);
    res.status(200).json({ message: "Deleted" });
  });
});

app.post("/api/transactions", authMiddleware, (req, res) => {
  const { userId, amount, date, type, description, select, category } = req.body;

  // console.log("date", date);
  const newDate = new Date(date);
  // console.log("New date", newDate);

  // console.log(select);
  const account_book_id = select.key;
  const account_book_name = select.label;

  // console.log(amount, date, type, description, select, categorySelected);

  const query =
    "INSERT INTO transactions ( user_id, account_book_id, account_book_name, amount, category, description, date, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
  const values = [
    userId,
    account_book_id,
    account_book_name,
    amount,
    category,
    description,
    newDate,
    type,
  ];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to create new transaction", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // console.log(result);
    res.status(200).json({ message: "New transaction added!" });
  });
});

app.get("/api/transactions", authMiddleware, (req, res) => {
  const { id } = req.headers;
  // console.log("id", id);

  const query = "SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC;";
  const values = [id];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to get transactions", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // console.log(results);
    res.status(200).json({ transactionList: results });
  });
});

app.delete("/api/transactions/:id", authMiddleware, (req, res) => {
  const id = req.params.id;
  // console.log("id", id);

  const query = "DELETE FROM transactions WHERE id = ?;";
  const values = [id];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to delete transaction", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // console.log(results);
    res.status(200).json({ message: "Deleted" });
  });
});

app.put("/api/transactions/:id", authMiddleware, (req, res) => {
  const transactionId = req.params.id;

  const { userId, amount, date, type, description, select, category } = req.body;

  const newDate = new Date(date);

  // console.log(select);
  const account_book_id = select.key;
  const account_book_name = select.label;

  const query = `
    UPDATE transactions 
    SET user_id = ?, 
        account_book_id = ?, 
        account_book_name = ?, 
        amount = ?, 
        category = ?, 
        description = ?, 
        date = ?, 
        type = ?
    WHERE id = ?
  `;

  const values = [
    userId,
    account_book_id,
    account_book_name,
    amount,
    category,
    description,
    newDate,
    type,
    transactionId,
  ];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to update transaction", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.status(200).json({ message: "Transaction updated successfully!" });
  });
});

app.get("/api/account-books-summary/:userId", authMiddleware, (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT 
      account_books.name AS account_book_name,
      SUM(CASE WHEN transactions.type = 'income' THEN transactions.amount ELSE 0 END) AS total_income,
      SUM(CASE WHEN transactions.type = 'expense' THEN transactions.amount ELSE 0 END) AS total_expense
    FROM account_books
    LEFT JOIN transactions ON account_books.id = transactions.account_book_id
    WHERE account_books.user_id = ?
    GROUP BY account_books.id, account_books.name
    ORDER BY account_books.name;
  `;

  const values = [userId];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to get account book summary", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.status(200).json(results);
  });
});

app.get("/api/monthly-summary/:userId", authMiddleware, (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT 
      DATE_FORMAT(date, '%Y-%m') AS month,
      SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) AS total_income,
      SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) AS total_expense
    FROM transactions
    WHERE user_id = ?
    GROUP BY month
    ORDER BY month;
  `;

  const values = [userId];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to get monthly summary", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.status(200).json(results);
  });
});

app.get("/api/top-categories/:userId", authMiddleware, (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT 
      category,
      SUM(amount) AS total
    FROM transactions
    WHERE user_id = ? AND type = 'expense'
    GROUP BY category
    ORDER BY total DESC
    LIMIT 5;
  `;

  const values = [userId];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to get top 5 categories", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.status(200).json(results);
  });
});

app.get("/api/category-ratio/:userId", authMiddleware, (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT 
      category,
      SUM(amount) AS total
    FROM transactions
    WHERE user_id = ? AND type = 'expense'
    GROUP BY category
    ORDER BY total DESC;
  `;

  const values = [userId];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error("Failed to get expense category ratio", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.status(200).json(results);
  });
});

app.listen(6789, () => {
  console.log("Server Listening on Port 6789...");
});
