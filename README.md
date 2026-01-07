# Penny Wave

A modern personal finance web application designed to help users manage daily income and expenses,
organize multiple account books, and build sustainable savings habits through flexible savings plans.

This project focuses on real-life usability, clean UI, and clear financial insights.

---

## 🖥️ Demo

This project is now live: [Penny Wave](https://pennywave.net)

Watch the demo video: [Demo Video](https://www.youtube.com/watch?v=-0Kt80Snxmk)

## ✨ Features

### 🧮 Dashboard 
**First-time Experience (Empty State)**

- User-friendly onboarding guide when no financial data is available
- Clear prompts to create an account book, add transactions, or start a savings plan

<img width="800" height="600" alt="empty-state" src="https://github.com/user-attachments/assets/795a2282-0f63-4a78-b358-6c0103280351" />
<br /><br />

**Financial Overview (With Data)**

- Monthly income and expense summary for the current month
- Savings plans progress overview 
- Monthly income vs expenses line chart for trend analysis
- Expense distribution pie chart by category
- Upcoming deposits for active savings plans
- Recent transactions list for quick review

 <img width="800" height="600" alt="dashboard" src="https://github.com/user-attachments/assets/db53888a-ef4a-4126-abdd-d26c5cd04f7c" />

  
### 📒 Account Books 
- Create and manage multiple account books (e.g. Daily Expenses, Travel, Family)
- View monthly income, expenses, and balance summaries

<img width="800" height="600" alt="account-books" src="https://github.com/user-attachments/assets/0bcf6844-17f0-4a27-870d-bae14787ecf9" />

### 💸 Transactions
- Record daily income and expenses with detailed transaction history
- Categorize transactions for better financial insights
- Recent transactions and quick status overview on the dashboard

<img width="800" height="600" alt="transactions" src="https://github.com/user-attachments/assets/1bf934f2-ee7f-4395-b4f4-876fc5beef00" />


### 💰 Savings Plans
- Create custom savings plans with target amounts and deadlines
- Track deposit progress in real time
- Support flexible and irregular deposits
- Visual progress indicators to encourage consistent saving
- Easily pause, complete, or adjust savings plans as financial situations change

<img width="800" height="600" alt="savings-plans" src="https://github.com/user-attachments/assets/f0acfbb1-fc31-4c39-98b5-d0e438e8fa87" />

---

## 🧱 Tech Stack

- Frontend: React, Redux, Ant Design, ECharts, Axios
- Backend: Node.js, Express, MySQL, Nodemailer, OAuth, JWT, bcrypt
- Database: MySQL


## 🏗️ Deployment

This project is deployed on AWS.

The complete deployment process and configuration are documented in a dedicated repository:
👉 [Penny Wave Deployment](https://github.com/jo-muuuuuu/penny-wave-deployment)

---

## 🚀 Getting Started
### Installation

```bash
git clone https://github.com/jo-muuuuuu/penny-wave-be.git
cd penny-wave-db
npm install
```

### Create a .env file with the following credentials
```
PUBLIC_IP
MYSQL_CONFIGURATION
JWT_SECRET

# For Nodemailer
EMAIL_USERNAME=noreply.pennywave@gmail.com
EMAIL_PASSWORD=vnashdpxtbgvwkjt

# Log-in via Google
GOOGLE_CLIENT_ID

# Log-in via GitHub
GITHUB_CLIENT_ID
GITHUB_CLIENT_SECRET
GITHUB_REDIRECT_URI
```

### Running the server
```
node app.js

# or use nodemon
# nodemon app.js
```
