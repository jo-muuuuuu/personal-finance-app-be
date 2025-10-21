# Personal Finance App - Back End
## Introduction
This project is a simple yet functional personal finance application that allows users to track their income and expenses using account books and transactions.

### Account Book Page
<img width="600" alt="1bc84159fa2f53b973fe35119ff3bce" src="https://github.com/user-attachments/assets/2732fabb-257f-4f7a-80e3-77016648e80e" />

### Transaction Page
<img width="600" alt="522a5e8ecc66eaae5ddd5dec637bd44" src="https://github.com/user-attachments/assets/7aeb1b86-bbc5-4582-90ae-6be5f016496c" />

### Dashboard
<img width="600" alt="4a9220e92a99e30cfc6622298c0e6d3" src="https://github.com/user-attachments/assets/cd87a0bb-f155-4079-81e7-5b700d6cf0fb" />


## Deployment
This project is now live: [Personal Finance App](http://16.26.46.247/)

### Database
The backend uses a `MySQL` database hosted on `Amazon RDS`.

### Frontend & Backend
Both the frontend and backend are deployed on a single `Amazon EC2` instance.
- `Nginx` is used to serve the frontend and proxy API requests to the backend.
- `PM2` is used to run and monitor the backend `Express` server.

## How to use
You can register a new account and log in to start using the app.

- For simplicity and demonstration purposes, there is no email or password validation during registration.
- If you'd like to test the `forgot password` and `reset password` functionalities, please use a ***real email address***.

## Tech Stack
- Frontend: React, React Redux, Ant Design, Axios, ECharts
- Backend: Node.js (Express.js), MySQL, Nodemailer (Gmail)
- DevOps & Hosting: AWS (EC2, RDS), Nginx, PM2


## Commands
- Connect to the RDS MySQL DB: `mysql -h <Endpoint of DB> -P 3306 -u <username> -p` and then enter password
- `MySQL scripts` are also available in the Backend Repo.
- Connect to the EC2 Instance: `ssh -i <key-pair.pem> <username>@<Public DNS of Instance>`
- Install necessary modules: `sudo yum install -y nodejs git nginx`, `sudo npm install -g pm2`
- Transfer files: `scp -i <key-pair.pem> -r <folder> <username>@<Public DNS of Instance>`, or `git clone <URL of your repo>`
- Strat Backend: `pm2 start <backend file> --name <name>`, `pm2 save`, `pm2 restart <name>`, `pm2 logs <name>`
- Modify Nginx configuration: `sudo nano /etc/nginx/nginx.conf`
- Use Nginx: `sudo systemctl start nginx`, `sudo systemctl enable nginx`, `sudo systemctl restart nginx`
