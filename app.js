const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
const dayjs = require("dayjs");

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
// console.log("mysqlConfig", mysqlConfig);

const pool = mysql.createPool(mysqlConfig);

const authMiddleware = (req, res, next) => {
  const token = req.headers.token;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, jwtSecretKey);
    // console.log("decoded", decoded);

    req.user = {
      userId: decoded.userId,
      email: decoded.email,
    };

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

app.post("/api/register", async (req, res) => {
  //   console.log(req.body);
  const { nickname, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = "INSERT INTO users (nickname, email, password) VALUES (?, ?, ?)";
    const values = [nickname, email, hashedPassword];

    await pool.query(query, values);

    res.status(200).json({ message: "New user registered!" });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "User already exists" });
    } else {
      console.error("Failed to create new user", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }
  }
});

app.post("/api/login", async (req, res) => {
  // console.log(req.body);
  const { email, password } = req.body;

  try {
    const query = "SELECT id, nickname, password, avatar_url FROM users WHERE email = ?;";
    const values = [email];
    const [results] = await pool.query(query, values); // return [rows, fields]

    if (results.length === 0) {
      return res.status(401).json({ error: "User does not exist" });
    }
    // console.log(results);
    const {
      id: userId,
      nickname,
      password: hashedPassword,
      avatar_url: avatarURL,
    } = results[0];

    const isMatch = await bcrypt.compare(password, hashedPassword);
    if (!isMatch) {
      return res.status(401).json({ error: "Wrong email or password!" });
    }

    const token = jwt.sign({ userId, email }, jwtSecretKey, {
      expiresIn: "1h",
    });

    res.status(200).json({ userId, nickname, email, avatarURL, token });
  } catch (error) {
    console.error("Failed to login:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/api/forgot-password", async (req, res) => {
  // console.log(req.body);
  const { email } = req.body;

  try {
    let query = "SELECT id FROM users WHERE email = ?;";
    let values = [email];
    const [results] = await pool.query(query, values);

    if (results.length === 0) {
      return res.status(401).json({ error: "Email not found" });
    }

    const token = jwt.sign({ email }, jwtSecretKey, { expiresIn: "15m" });
    const expiration = new Date(Date.now() + 900000);

    query =
      "UPDATE users SET reset_token = ?, reset_token_expiration = ? WHERE email = ?;";
    values = [token, expiration, email];
    await pool.query(query, values);

    const mailOptions = {
      from: process.env.EMAIL_USERNAME,
      to: email,
      subject: "Penny Wave - Password Reset",
      text: `Click the link to reset your password: ${process.env.PUBLIC_IP}/reset-password/${token}`,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: "Password reset email sent!" });
  } catch (error) {
    console.error("Failed to process forgot password:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/validate-token", async (req, res) => {
  const { token } = req.query;

  try {
    jwt.verify(token, jwtSecretKey);

    const query =
      "SELECT * FROM users WHERE reset_token = ? AND reset_token_expiration > NOW();";
    const values = [token];

    const [results] = await pool.query(query, values);

    if (results.length === 0) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    res.status(200).json({ message: "Token is valid" });
  } catch (error) {
    console.error("Failed to validate token", error);

    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  // console.log("req.body", req.body);
  const { email } = req.user;
  const { newPassword } = req.body;

  try {
    // const decoded = jwt.verify(token, jwtSecretKey);
    // const email = decoded.email;

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const query =
      "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiration = NULL WHERE email = ?;";
    const values = [hashedPassword, email];

    const [results] = await pool.query(query, values);

    if (results.affectedRows === 0) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    res.status(200).json({ message: "Password updated successfully!" });
  } catch (error) {
    if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
      console.error("JWT validation failed:", error.message);
      return res.status(401).json({ error: "Invalid or expired token" });
    } else {
      console.error("Unexpected error:", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }
  }
});

app.post("/api/profile-reset-password", authMiddleware, async (req, res) => {
  const { email } = req.user;
  const { oldPassword, newPassword } = req.body;

  try {
    // const decoded = jwt.verify(token, jwtSecretKey);
    // const email = decoded.username;

    let query = "SELECT password FROM users WHERE email = ?;";
    let values = [email];
    const [results] = await pool.query(query, values);

    if (results.length === 0) {
      return res.status(401).json({ error: "User does not exist" });
    }

    const { password: hashedPassword } = results[0];
    const isMatch = await bcrypt.compare(oldPassword, hashedPassword);
    if (!isMatch) {
      return res.status(401).json({ error: "Incorrect old password!" });
    }

    const newHashedPassword = await bcrypt.hash(newPassword, 10);
    query =
      "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiration = NULL WHERE email = ?;";
    values = [newHashedPassword, email];

    const [result] = await pool.query(query, values);
    if (result.affectedRows === 0) {
      return res.status(500).json({ error: "Password update failed" });
    }

    res.status(200).json({ message: "Password updated successfully!" });
  } catch (error) {
    if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Invalid or expired token" });
    } else {
      console.error("Failed to reset password:", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }
  }
});

app.post(
  "/api/upload-avatar",
  authMiddleware,
  upload.single("image"),
  async (req, res) => {
    const { email } = req.user;
    const avatarPath = `/uploads/${req.file.filename}`;

    try {
      const query = "UPDATE users SET avatar_url = ? WHERE email = ?";
      const values = [avatarPath, email];
      await pool.query(query, values);

      res.status(200).json({
        message: "Avatar uploaded successfully",
        avatarURL: avatarPath,
      });
    } catch (err) {
      console.error("Upload avatar error:", err);
      res.status(500).json({ error: "Failed to upload avatar" });
    }
  }
);

app.post("/api/account-books", authMiddleware, async (req, res) => {
  const { userId } = req.user;
  const { name, tag, description } = req.body;

  try {
    const query =
      "INSERT INTO account_books (user_id, name, tag, description) VALUES (?, ?, ?, ?)";
    const values = [userId, name, tag, description];
    await pool.query(query, values);
    res.status(200).json({ message: "New account book created!" });
  } catch (error) {
    console.error("Failed to create new account book", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/api/account-books/:id", authMiddleware, async (req, res) => {
  // console.log("req.body", req.body);
  const { userId } = req.user;
  const { name, tag, description } = req.body;
  const accountBookId = req.params.id;

  try {
    const query =
      "UPDATE account_books SET user_id = ?, name = ?, tag = ?, description = ? WHERE id = ?;";
    const values = [userId, name, tag, description, accountBookId];
    await pool.query(query, values);
    res.status(200).json({ message: "Accound book updated!" });
  } catch (error) {
    console.error("Failed to update account book", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/account-books", authMiddleware, async (req, res) => {
  const { userId } = req.user;

  try {
    const query =
      "SELECT * FROM account_books WHERE user_id = ? ORDER BY created_at DESC;";
    const values = [userId];
    const [results] = await pool.query(query, values);
    res.status(200).json({ accountBookList: results });
  } catch (error) {
    console.error("Failed to get account books", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.delete("/api/account-books/:id", authMiddleware, async (req, res) => {
  const accountBookId = req.params.id;

  try {
    const query = "DELETE FROM account_books WHERE id = ?;";
    const values = [accountBookId];
    await pool.query(query, values);
    res.status(200).json({ message: "Deleted" });
  } catch (error) {
    console.error("Failed to delete account book", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/api/transactions", authMiddleware, async (req, res) => {
  const { userId } = req.user;
  const { amount, date, type, description, select, category } = req.body;

  const newDate = new Date(date);
  const account_book_id = select.key;
  const account_book_name = select.label;

  // console.log(amount, date, type, description, select, categorySelected);
  try {
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

    await pool.query(query, values);
    res.status(200).json({ message: "New transaction added!" });
  } catch (error) {
    console.error("Failed to create new transaction", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/transactions", authMiddleware, async (req, res) => {
  const { userId } = req.user;

  try {
    const query =
      "SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC;";
    const values = [userId];
    const [results] = await pool.query(query, values);
    res.status(200).json({ transactionList: results });
  } catch (error) {
    console.error("Failed to get transactions", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.delete("/api/transactions/:id", authMiddleware, async (req, res) => {
  // console.log("id", id);
  const id = req.params.id;

  try {
    const query = "DELETE FROM transactions WHERE id = ?;";
    const values = [id];
    await pool.query(query, values);
    res.status(200).json({ message: "Deleted" });
  } catch (error) {
    console.error("Failed to delete transaction", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/api/transactions/:id", authMiddleware, async (req, res) => {
  const transactionId = req.params.id;
  const { userId } = req.user;
  const { amount, date, type, description, select, category } = req.body;

  const newDate = new Date(date);
  const account_book_id = select.key;
  const account_book_name = select.label;

  try {
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
    await pool.query(query, values);
    res.status(200).json({ message: "Transaction updated successfully!" });
  } catch (error) {
    console.error("Failed to update transaction", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

function calculateNewEndDate(end_date, period, periods) {
  const start = dayjs(end_date);
  let newEndDate;

  switch (period) {
    case "week":
      newEndDate = start.add(periods, "week");
      break;
    case "fortnight":
      newEndDate = start.add(periods * 2, "week");
      break;
    case "month":
      newEndDate = start.add(periods, "month");
      break;
    case "quarter":
      newEndDate = start.add(periods * 3, "month");
      break;
    case "year":
      newEndDate = start.add(periods, "year");
      break;
    default:
      newEndDate = start;
  }

  // console.log("Calculated new end date:", newEndDate.format("YYYY-MM-DD"));
  return newEndDate;
}

function generateDepositDates(startDate, endDate, period, totalPeriods) {
  const depositDates = [];
  // console.log("received", startDate, endDate, period, totalPeriods);

  if (!startDate || !endDate || !period || !totalPeriods) {
    console.warn("generateDepositDates: Missing required parameters.");
    return depositDates;
  }

  const start = dayjs(startDate);
  const end = dayjs(endDate);

  if (!start.isValid() || !end.isValid()) {
    console.warn("generateDepositDates: Invalid date parameters.");
    return depositDates;
  }

  for (let i = 0; i < totalPeriods; i++) {
    let nextDate;

    switch (period) {
      case "week":
        nextDate = start.add(i * 7, "day");
        break;
      case "fortnight":
        nextDate = start.add(i * 14, "day");
        break;
      case "month":
        nextDate = start.add(i, "month");
        break;
      case "quarter":
        nextDate = start.add(i * 3, "month");
        break;
      case "year":
        nextDate = start.add(i, "year");
        break;
      default:
        console.warn(`Unsupported period type: ${period}`);
        return depositDates;
    }

    if (nextDate.isAfter(end)) break;

    const formatted = nextDate.format("YYYY-MM-DD");
    depositDates.push(formatted);
  }

  return depositDates;
}

app.post("/api/savings-plans", authMiddleware, async (req, res) => {
  // console.log("req.body", req.body);
  const { userId } = req.user;
  const {
    name,
    description,
    start_date,
    end_date,
    amount,
    period,
    totalPeriods,
    amountPerPeriod,
  } = req.body;

  const newStartDate = new Date(start_date);
  const newEndDate = new Date(end_date);

  try {
    let query =
      "INSERT INTO savings_plans (user_id, name, description, start_date, end_date, amount, period, total_periods, amount_per_period) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    let values = [
      userId,
      name,
      description,
      newStartDate,
      newEndDate,
      amount,
      period,
      totalPeriods,
      amountPerPeriod,
    ];

    const [results] = await pool.query(query, values);

    const depositDates = generateDepositDates(
      newStartDate,
      newEndDate,
      period,
      totalPeriods
    );

    let depositList = [];
    depositDates.forEach((date) => {
      depositList.push([
        results.insertId,
        userId,
        amountPerPeriod,
        amountPerPeriod,
        date,
        "pending",
      ]);
    });

    query =
      "INSERT INTO deposits (plan_id, user_id, scheduled_amount, deposited_amount, date, status) VALUES ?";
    values = [depositList];

    await pool.query(query, values);
    res.status(200).json({ message: "New savings plan created!" });
  } catch (error) {
    console.error("Failed to create new savings plan", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/savings-plans", authMiddleware, async (req, res) => {
  const { userId } = req.user;

  try {
    const query =
      "SELECT * FROM savings_plans WHERE user_id = ? ORDER BY created_at DESC;";
    const values = [userId];
    const [results] = await pool.query(query, values);
    res.status(200).json({ savingsPlanList: results });
  } catch (error) {
    console.error("Failed to get savings plans", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

// app.get("/api/savings-plans/:id", authMiddleware, async (req, res) => {
//   const savingsPlanId = req.params.id;
//   // console.log("id", savingsPlanId);

//   try {
//     const query = "SELECT * FROM savings_plans WHERE id = ?;";
//     const values = [savingsPlanId];
//     const [results] = await pool.query(query, values);
//     res.status(200).json({ savingsPlan: results[0] });
//   } catch (error) {
//     console.error("Failed to get savings plans", error);
//     return res.status(500).json({ error: "Internal Server Error" });
//   }
// });

app.delete("/api/savings-plans/:id", authMiddleware, async (req, res) => {
  // console.log("id", id);
  const savingsPlanId = req.params.id;

  try {
    const query = "DELETE FROM savings_plans WHERE id = ?;";
    const values = [savingsPlanId];

    await pool.query(query, values);

    res.status(200).json({ message: "Deleted" });
  } catch (error) {
    console.error("Failed to delete savings plan", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

// update savings plan
app.put("/api/savings-plans/:id", authMiddleware, async (req, res) => {
  // console.log(req.body);
  const savingsPlanId = req.params.id;
  const { userId } = req.user;
  const {
    name,
    description,
    remaining_amount,
    remaining_periods,
    new_total_amount,
    new_end_date,
  } = req.body;

  const newEndDate = new Date(new_end_date);

  try {
    // get savings plan details
    let query = "SELECT * FROM savings_plans WHERE id = ?;";
    let values = [savingsPlanId];
    const [results] = await pool.query(query, values);

    // console.log("results", results);
    const plan = results[0];

    const new_total_periods = plan.completed_periods + remaining_periods;
    const new_amount_per_period = remaining_amount / remaining_periods;

    const flagOne = new_total_amount === plan.amount;
    const flagTwo = remaining_periods === plan.total_periods - plan.completed_periods;

    if (!flagOne || !flagTwo) {
      // delete future deposits
      query = "DELETE FROM deposits WHERE plan_id = ? AND status = 'pending';";
      values = [savingsPlanId];
      await pool.query(query, values);

      // generate new deposits
      const nextDepositDate = calculateNewEndDate(
        plan.start_date,
        plan.period,
        plan.completed_periods
      );

      const depositDates = generateDepositDates(
        nextDepositDate,
        newEndDate,
        plan.period,
        remaining_periods
      );

      let depositList = [];
      depositDates.forEach((date) => {
        depositList.push([
          savingsPlanId,
          userId,
          new_amount_per_period,
          new_amount_per_period,
          date,
          "pending",
        ]);
      });

      query =
        "INSERT INTO deposits (plan_id, user_id, scheduled_amount, deposited_amount, date, status) VALUES ?";
      values = [depositList];
      await pool.query(query, values);
    }

    // update savings plan
    query =
      "UPDATE savings_plans SET name = ?, description = ?, amount = ?, total_periods = ?, amount_per_period = ?, end_date = ? WHERE id = ?;";
    values = [
      name,
      description,
      new_total_amount,
      new_total_periods,
      new_amount_per_period,
      newEndDate,
      savingsPlanId,
    ];
    await pool.query(query, values);

    res.status(200).json({ message: "Savings plan updated!" });
  } catch (error) {
    console.error("Failed to update savings plan", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/deposits", authMiddleware, async (req, res) => {
  // console.log(req.headers);
  const { savingsplanid: savingsPlanId } = req.headers;

  try {
    const query = "SELECT * FROM deposits WHERE plan_id = ?;";
    const values = [savingsPlanId];
    const [results] = await pool.query(query, values);

    res.status(200).json({ depositList: results });
  } catch (error) {
    console.error("Failed to get deposits", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/api/deposits/:id", authMiddleware, async (req, res) => {
  // console.log("req.body", req.body);
  const {
    id: depositId,
    deposited_amount,
    plan_id: savingsPlanId,
    editableAmount,
  } = req.body;

  const finalAmount = editableAmount ? +editableAmount : +deposited_amount;
  try {
    // update deposit status and amount
    let query =
      "UPDATE deposits SET status = 'completed', deposited_amount = ? WHERE id = ?;";
    let values = [finalAmount, depositId];
    await pool.query(query, values);

    // get savings plan details
    query = "SELECT * FROM savings_plans WHERE id = ?;";
    values = [savingsPlanId];
    const [results] = await pool.query(query, values);

    // console.log("results", results);
    const plan = results[0];

    // Check remaining amount and periods
    const remainingAmount = +plan.amount - +plan.deposited_amount;
    const remainingPeriods = +plan.total_periods - +plan.completed_periods;

    // Check if savings plan is completed
    if (finalAmount >= remainingAmount) {
      if (remainingPeriods > 1) {
        // Delete future pending deposits
        query = "DELETE FROM deposits WHERE plan_id = ? AND status = 'pending';";
        values = [savingsPlanId];
        await pool.query(query, values);
      }

      query =
        "UPDATE savings_plans SET amount = ?, completed_periods = completed_periods + 1, deposited_amount = deposited_amount + ?, status = 'completed' WHERE id = ?";
      values = [+plan.amount + finalAmount - remainingAmount, finalAmount, savingsPlanId];

      await pool.query(query, values);

      return res
        .status(200)
        .json({ message: "Deposit confirmed! Savings plan completed." });
    } else {
      if (remainingPeriods === 1) {
        // Savings plan uncompleted but last period, generate one more deposit
        const newEndDate = calculateNewEndDate(plan.end_date, plan.period, 1);

        query =
          "INSERT INTO deposits (plan_id, user_id, scheduled_amount, deposited_amount, date, status) VALUES (?, ?, ?, ?, ?);";
        values = [
          savingsPlanId,
          plan.user_id,
          +plan.amount - (+plan.deposited_amount + finalAmount),
          +plan.amount - (+plan.deposited_amount + finalAmount),
          newEndDate,
          "pending",
        ];
        await pool.query(query, values);
      } else {
        // Savings Plan uncompleted, update future pending deposits amount
        const newAmountPerPeriod =
          (+plan.amount - (+plan.deposited_amount + finalAmount)) /
          (remainingPeriods - 1);

        query =
          "UPDATE deposits SET deposited_amount = ? WHERE plan_id = ? AND status = 'pending';";
        values = [newAmountPerPeriod, savingsPlanId];
        await pool.query(query, values);
      }

      // update savings plan completed_periods and deposited_amount
      query =
        "UPDATE savings_plans SET completed_periods = completed_periods + 1, deposited_amount = deposited_amount + ? WHERE id = ?";
      values = [finalAmount, savingsPlanId];
      await pool.query(query, values);

      res.status(200).json({ message: "Deposit confirmed!" });
    }
  } catch (error) {
    console.error("Failed to deposit", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/api/deposits/reset/:id", authMiddleware, async (req, res) => {
  // console.log(req.body);
  const { id: depositId, plan_id: savingsPlanId, deposited_amount } = req.body;

  try {
    let query = "SELECT * FROM deposits WHERE id = ?";
    let values = [depositId];
    const [results] = await pool.query(query, values);
    const deposit = results[0];

    const { scheduled_amount } = deposit;

    query = "UPDATE deposits SET deposited_amount = ?, status = 'pending' WHERE id = ?;";
    values = [scheduled_amount, depositId];
    await pool.query(query, values);

    query =
      "UPDATE savings_plans SET completed_periods = completed_periods - 1, deposited_amount = deposited_amount - ?, status = 'active' WHERE id = ?";
    values = [deposited_amount, savingsPlanId];
    await pool.query(query, values);

    query = "SELECT * FROM savings_plans WHERE id = ?";
    values = [savingsPlanId];
    const [plans] = await pool.query(query, values);
    // console.log("plans", plans);
    const plan = plans[0];

    const newAmount =
      (+plan.amount - +plan.deposited_amount) /
      (+plan.total_periods - +plan.completed_periods);

    query =
      "UPDATE deposits SET deposited_amount = ? WHERE plan_id = ? AND status = 'pending';";
    values = [newAmount, savingsPlanId];
    await pool.query(query, values);

    res.status(200).json({ message: "Deposit Reset!" });
  } catch (error) {
    console.error("Failed to reset deposit", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/account-books-summary/:userId", authMiddleware, async (req, res) => {
  const userId = req.params.userId;

  try {
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

    const [results] = await pool.query(query, values);

    res.status(200).json(results);
  } catch (error) {
    console.error("Failed to get account book summary", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/monthly-summary/:userId", authMiddleware, async (req, res) => {
  const userId = req.params.userId;

  try {
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
    const [results] = await pool.query(query, values);
    res.status(200).json(results);
  } catch (error) {
    console.error("Failed to get monthly summary", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/top-categories/:userId", authMiddleware, async (req, res) => {
  const userId = req.params.userId;

  try {
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

    const [results] = await pool.query(query, values);

    res.status(200).json(results);
  } catch (error) {
    console.error("Failed to get top 5 categories", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/category-ratio/:userId", authMiddleware, async (req, res) => {
  const userId = req.params.userId;

  try {
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

    const [results] = await pool.query(query, values);
    res.status(200).json(results);
  } catch (error) {
    console.error("Failed to get expense category ratio", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.listen(6789, () => {
  console.log("Server Listening on Port 6789...");
});
