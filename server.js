const express = require("express");

const app = express();

const PORT = process.env.PORT || 3000;

// Allows the API to read JSON sent by Android
app.use(express.json());

const users = [
  {
    LastName: "Solon",
    FirstName: "Lucas",
    Email: "Lucas@email.com",
    Password: "12345"
  },
  {
    LastName: "name",
    FirstName: "namename",
    Email: "name@email.com",
    Password: "nameemail1"
  },
  {
    LastName: "email",
    FirstName: "lastemail",
    Email: "email@name.com",
    Password: "2444123"
  }
];

// Stores OTPs temporarily
const otpStore = new Map();


// ===============================
// HOME
// ===============================

app.get("/", (req, res) => {
  res.send("Users API is running!");
});


// ===============================
// USERS
// ===============================

app.get("/users", (req, res) => {
  res.json(users);
});


// ===============================
// REQUEST OTP
// ===============================

app.post("/otp/request", (req, res) => {

  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      success: false,
      message: "Email is required"
    });
  }

  // Check if email exists
  const user = users.find(
    u => u.Email.toLowerCase() === email.toLowerCase()
  );

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "User not found"
    });
  }

  // Generate random 4-digit OTP
  const otp = Math.floor(1000 + Math.random() * 9000).toString();

  // OTP expires after 30 seconds
  const expiresAt = Date.now() + 30000;

  // Save OTP
  otpStore.set(email.toLowerCase(), {
    otp: otp,
    expiresAt: expiresAt
  });

  // OTP appears ONLY in Render logs
  console.log("--------------------------------");
  console.log(`OTP for ${email}: ${otp}`);
  console.log("OTP expires in 30 seconds");
  console.log("--------------------------------");

  res.json({
    success: true,
    message: "OTP generated",
    expiresIn: 30
  });
});


// ===============================
// VERIFY OTP
// ===============================

app.post("/otp/verify", (req, res) => {

  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({
      success: false,
      message: "Email and OTP are required"
    });
  }

  const savedOtp =
    otpStore.get(email.toLowerCase());

  if (!savedOtp) {
    return res.status(400).json({
      success: false,
      message: "No OTP found"
    });
  }

  // Check expiration
  if (Date.now() > savedOtp.expiresAt) {

    otpStore.delete(email.toLowerCase());

    return res.status(400).json({
      success: false,
      expired: true,
      message: "OTP expired"
    });
  }

  // Check if OTP is correct
  if (otp.toString() !== savedOtp.otp) {

    return res.status(400).json({
      success: false,
      expired: false,
      message: "Invalid OTP"
    });
  }

  // OTP is correct, remove it so it can't be reused
  otpStore.delete(email.toLowerCase());

  return res.json({
    success: true,
    message: "OTP verified"
  });
});


// ===============================
// START SERVER
// ===============================

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
