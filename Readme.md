# Day 12: Authentication & Authorization 🔐

Welcome to Day 12 of the Backend Development Cohort! Today's lecture focused on the core concepts of **Authentication** and **Authorization**, implementing them using **JWT (JSON Web Tokens)** and **Cookies**.

---

## 📖 Theory & Concepts

### 1. Authentication vs. Authorization

- **Authentication (AuthN):** The process of verifying **who** a user is (e.g., Login).
- **Authorization (AuthZ):** The process of verifying **what** a user can do (e.g., Accessing a specific resource).

### 2. JSON Web Token (JWT)

JWT is a compact, URL-safe means of representing claims to be transferred between two parties. It consists of three parts separated by dots (`.`):

- **Header:** Contains the algorithm and token type.
- **Payload:** Contains the data (claims) like `userId`, `email`, etc.
- **Signature:** Used to verify that the sender is who they say they are and to ensure the message wasn't changed along the way.

### 3. Cookies 🍪

Cookies are small pieces of data sent from a server and stored on the user's computer by the user's web browser while the user is browsing.

- **Why Cookies for JWT?** They can be automatically sent with every request, and if configured correctly (HttpOnly), they provide a more secure way to store tokens compared to LocalStorage.

---

## 🛠 Project Setup

### 1. Code Imports & Requires

To handle authentication, you need the following core packages:

```javascript
const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto"); // Used for hashing in this lecture
```

### 2. Required Packages

Install these dependencies in your project:

```bash
npm install express jsonwebtoken cookie-parser mongoose dotenv
```

---

## 🚀 Implementation Steps

### Step 1: User Model

Define your user schema using Mongoose. Ensure the email is unique to avoid duplicate registrations.

### Step 2: Password Hashing (The simple way)

Before saving a user to the database, hash the password. In this lecture, we used MD5 hashing via the `crypto` module:

```javascript
const hashedPassword = crypto.createHash("md5").update(password).digest("hex");
```

_Note: MD5 is used here for learning purposes. In production, always use `bcrypt`._

### Step 3: Generating the Token (JWT)

Once the user is registered or logged in successfully, generate a JWT.

```javascript
const token = jwt.sign(
  { id: user._id, email: user.email }, // Payload
  process.env.JWT_SECRET, // Secret Key
  { expiresIn: "1h" }, // Expiry
);
```

### Step 4: Storing Token in Cookie

Send the generated token to the client via a cookie.

```javascript
res.cookie("token", token);
```

### Step 5: Verifying the User (Protected Routes)

To verify a user, extract the token from cookies and verify it using JWT.

```javascript
const token = req.cookies.token;
const decoded = jwt.verify(token, process.env.JWT_SECRET);
```

---

## 📁 Folder Structure

```text
Day-12-Auth/
├── src/
│   ├── config/      # Database connection
│   ├── models/      # User Schemas
│   ├── routes/      # Auth routes (Register, Login, GetMe)
│   └── app.js       # Express app setup
├── server.js        # Server entry point
└── .env             # Environment variables (JWT_SECRET, MONGO_URI)
```

## 🔗 API Endpoints

| Method | Endpoint             | Description                                   |
| :----- | :------------------- | :-------------------------------------------- |
| `POST` | `/api/auth/register` | Register a new user and get token             |
| `POST` | `/api/auth/login`    | Login existing user and get token             |
| `GET`  | `/api/auth/get-me`   | Get current user's profile using cookie token |

---

## 💡 Key Learnings from Lecture

- Always use `cookie-parser` middleware to read cookies in Express.
- Store sensitive data like `JWT_SECRET` in `.env` files.
- MD5 is a fast hashing algorithm but not recommended for production passwords (use `bcrypt` instead).
- JWT provides a stateless way to handle authentication.

---

_Happy Coding! 🚀_

