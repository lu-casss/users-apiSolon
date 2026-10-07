const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

const otpStore = new Map();

app.get("/", (req, res) => {
    res.send("Users API is running!");
});

// USERS LIST
app.get("/users", async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, full_name, email FROM users ORDER BY id"
        );

        res.json(result.rows);

    } catch (error) {
        console.error("Users error:", error.message);

        res.status(500).json({
            success: false,
            message: "Database error"
        });
    }
});

// SIGN UP
app.post("/signup", async (req, res) => {
    try {
        const { fullName, email, password } = req.body;

        if (
            typeof fullName !== "string" ||
            typeof email !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }

        const name = fullName.trim();
        const normalizedEmail =
            email.trim().toLowerCase();

        if (!name || !normalizedEmail || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
            return res.status(400).json({
                success: false,
                message: "Invalid email address"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message: "Password must be at least 6 characters"
            });
        }

        const hashedPassword =
            await bcrypt.hash(password, 10);

        await pool.query(
            `INSERT INTO users
             (full_name, email, password_hash)
             VALUES ($1, $2, $3)`,
            [
                name,
                normalizedEmail,
                hashedPassword
            ]
        );

        res.status(201).json({
            success: true,
            message: "Account created successfully!"
        });

    } catch (error) {

        if (error.code === "23505") {
            return res.status(409).json({
                success: false,
                message: "Email already exists"
            });
        }

        console.error("Signup error:", error.message);

        res.status(500).json({
            success: false,
            message: "Unable to create account"
        });
    }
});

// LOGIN
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (
            typeof email !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required"
            });
        }

        const normalizedEmail =
            email.trim().toLowerCase();

        const result = await pool.query(
            "SELECT * FROM users WHERE email = $1",
            [normalizedEmail]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }

        const user = result.rows[0];

        const validPassword =
            await bcrypt.compare(
                password,
                user.password_hash
            );

        if (!validPassword) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }

        res.json({
            success: true,
            message: "Login successful!",
            email: user.email,
            fullName: user.full_name
        });

    } catch (error) {

        console.error("Login error:", error.message);

        res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});

// RENDER OTP - SAVED FOR FUTURE ACTIVITY
app.post("/otp/request", async (req, res) => {
    try {
        const { email } = req.body;

        if (typeof email !== "string" || !email.trim()) {
            return res.status(400).json({
                success: false,
                message: "Email is required"
            });
        }

        const normalizedEmail =
            email.trim().toLowerCase();

        const result = await pool.query(
            "SELECT id FROM users WHERE email = $1",
            [normalizedEmail]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const otp =
            crypto.randomInt(1000, 10000).toString();

        otpStore.set(normalizedEmail, {
            otp: otp,
            expiresAt: Date.now() + 30000
        });

        console.log(
            `OTP for ${normalizedEmail}: ${otp}`
        );

        res.json({
            success: true,
            message: "OTP generated",
            expiresIn: 30
        });

    } catch (error) {

        res.status(500).json({
            success: false,
            message: "Unable to generate OTP"
        });
    }
});

app.post("/otp/verify", (req, res) => {

    const { email, otp } = req.body;

    if (
        typeof email !== "string" ||
        !email.trim() ||
        typeof otp !== "string"
    ) {
        return res.status(400).json({
            success: false,
            message: "Email and OTP are required"
        });
    }

    const key =
        email.trim().toLowerCase();

    const saved =
        otpStore.get(key);

    if (!saved) {
        return res.status(400).json({
            success: false,
            message: "No OTP found"
        });
    }

    if (Date.now() >= saved.expiresAt) {

        otpStore.delete(key);

        return res.status(400).json({
            success: false,
            expired: true,
            message: "OTP expired"
        });
    }

    if (otp !== saved.otp) {
        return res.status(400).json({
            success: false,
            message: "Invalid OTP"
        });
    }

    otpStore.delete(key);

    res.json({
        success: true,
        message: "OTP verified"
    });
});

// DATABASE SETUP
async function startServer() {

    try {

        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                username TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        `);

        // Existing table originally required username.
        // Make username optional for the updated activity.
        await pool.query(`
            ALTER TABLE users
            ALTER COLUMN username DROP NOT NULL
        `);

        console.log(
            "PostgreSQL connected successfully!"
        );

        app.listen(PORT, "0.0.0.0", () => {
            console.log(
                `Server running on port ${PORT}`
            );
        });

    } catch (error) {

        console.error(
            "Database connection failed:",
            error.message
        );

        process.exit(1);
    }
}

startServer();
