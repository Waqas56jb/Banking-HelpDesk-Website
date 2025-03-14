const express = require("express");
const mysql = require("mysql");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
const { google } = require("googleapis");
const fs = require("fs");
const { OAuth2Client } = require("google-auth-library");

const app = express();
const port = 3000;

// Database Connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "1234", // Replace with your MySQL password
    database: "helpdesk",
});

db.connect((err) => {
    if (err) {
        console.error("Database connection failed:", err.stack);
        process.exit(1);
    }
    console.log("Connected to MySQL database.");
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use("/uploads", express.static("uploads"));
app.use(express.static("."));

// File Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = "uploads/";
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    },
});
const upload = multer({ storage: storage });

// Google OAuth2 Setup
const credentials = JSON.parse(fs.readFileSync("credentials.json"));
const { client_secret, client_id, redirect_uris } = credentials.installed;
const oAuth2Client = new OAuth2Client(client_id, client_secret, redirect_uris[0]);
const TOKEN_PATH = "token.json";

// Initialize Google Auth
async function initializeAuth() {
    try {
        if (fs.existsSync(TOKEN_PATH)) {
            const token = JSON.parse(fs.readFileSync(TOKEN_PATH));
            oAuth2Client.setCredentials(token);
            if (token.expiry_date && token.expiry_date < Date.now()) {
                const { credentials: newTokens } = await oAuth2Client.refreshAccessToken();
                fs.writeFileSync(TOKEN_PATH, JSON.stringify(newTokens));
                oAuth2Client.setCredentials(newTokens);
                console.log("Token refreshed and saved to", TOKEN_PATH);
            }
        } else {
            console.error("No token found. Please generate token.json first.");
            process.exit(1);
        }
    } catch (error) {
        console.error("Error initializing auth:", error.message);
        throw error;
    }
}

oAuth2Client.on("tokens", (tokens) => {
    if (tokens.refresh_token) {
        fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens));
        console.log("Token refreshed and saved to", TOKEN_PATH);
    }
    oAuth2Client.setCredentials(tokens);
});

const gmail = google.gmail({ version: "v1", auth: oAuth2Client });

// Email Sending Function
async function sendTicketEmail(to, ticketData) {
    const sender = "your_email@gmail.com"; // Replace with your Gmail address
    const subject = "Your Helpdesk Support Ticket Details";
    const message = `
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <h2 style="color: #00e676;">Your Support Ticket</h2>
            <p>Thank you for submitting your ticket! Below are the details:</p>
            <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 20px auto;">
                <p><strong>Issue Type:</strong> ${ticketData.issue_type}</p>
                <p><strong>Name:</strong> ${ticketData.name}</p>
                <p><strong>Email:</strong> ${ticketData.email}</p>
                <p><strong>Priority:</strong> ${ticketData.priority}</p>
                <p><strong>Branch Code:</strong> ${ticketData.branchcode}</p>
                <p><strong>Address:</strong> ${ticketData.address}</p>
                <p><strong>User Code:</strong> ${ticketData.user_code}</p>
                <p><strong>Subject:</strong> ${ticketData.subject}</p>
                <p><strong>Message:</strong> ${ticketData.message}</p>
                ${ticketData.attachment1 ? `<p><strong>Attachment:</strong> <a href="http://localhost:3000/uploads/${ticketData.attachment1}">${ticketData.attachment1}</a></p>` : ""}
                <p><strong>Ticket ID:</strong> ${ticketData.ticket_id}</p>
                <p><strong>Submission Date:</strong> ${new Date(ticketData.submission_date).toLocaleString()}</p>
            </div>
            <p style="text-align: center;">Track your ticket at <a href="http://localhost:3000/trace.html">Track Your Ticket</a></p>
        </body>
        </html>
    `;

    const email = [
        `From: ${sender}`,
        `To: ${to}`,
        `Subject: ${subject}`,
        "MIME-Version: 1.0",
        "Content-Type: text/html; charset=utf-8",
        "",
        message,
    ].join("\n");

    const encodedMessage = Buffer.from(email)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

    try {
        const response = await gmail.users.messages.send({
            userId: "me",
            requestBody: { raw: encodedMessage },
        });
        console.log("Email sent successfully:", response.data.id);
        return response;
    } catch (error) {
        console.error("Error sending email:", error.message);
        throw error;
    }
}

// Ticket Submission
app.post("/submit-ticket", upload.single("attachment1"), async (req, res) => {
    const { issue_type, name, email, priority, branchcode, address, user_code, subject, message } = req.body;
    const attachment1 = req.file ? req.file.filename : null;

    if (!issue_type || !name || !email || !priority || !branchcode || !address || !user_code || !subject || !message) {
        return res.status(400).json({ message: "All fields are required." });
    }

    const branchcodeInt = parseInt(branchcode, 10);
    if (isNaN(branchcodeInt)) {
        return res.status(400).json({ message: "Branch code must be a number." });
    }

    const sql = `
        INSERT INTO support_tickets (
            issue_type, name, email, priority, branchcode, address, user_code, subject, message, attachment1
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [issue_type, name, email, priority, branchcodeInt, address, user_code, subject, message, attachment1];

    try {
        await initializeAuth();
        const insertResult = await new Promise((resolve, reject) => {
            db.query(sql, values, (err, result) => {
                if (err) reject(err);
                else resolve(result);
            });
        });

        const ticket_id = insertResult.insertId;
        const ticketData = {
            issue_type, name, email, priority, branchcode: branchcodeInt, address, user_code, subject, message, attachment1, ticket_id, submission_date: new Date()
        };

        await sendTicketEmail(email, ticketData);
        res.json({ message: "Ticket submitted and email sent successfully!", ticket_id });
    } catch (error) {
        console.error("Error in ticket submission:", error.message);
        res.status(500).json({ message: "Error submitting ticket: " + error.message });
    }
});

// Track Ticket
app.post("/track-ticket", (req, res) => {
    const { email, ticket_id } = req.body;

    if (!email || !ticket_id) {
        return res.status(400).json({ message: "Email and Ticket ID are required." });
    }

    const sql = "SELECT * FROM support_tickets WHERE email = ? AND ticket_id = ?";
    db.query(sql, [email, ticket_id], (err, results) => {
        if (err) {
            console.error("Database query error:", err.message);
            return res.status(500).json({ message: "Error retrieving ticket: " + err.message });
        }
        if (results.length === 0) {
            return res.status(404).json({ message: "No ticket found with this email and ticket ID." });
        }
        res.json(results[0]);
    });
});

// Fetch All Tickets
app.get("/api/tickets", (req, res) => {
    const query = `
        SELECT ticket_id, issue_type, name, email, priority, branchcode, address, 
               user_code, subject, message, attachment1, submission_date 
        FROM support_tickets 
        ORDER BY submission_date DESC
    `;
    db.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching tickets:", err.message);
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});

// Delete Ticket
app.delete('/api/tickets/:id', (req, res) => {
    const ticketId = req.params.id;
    const sql = 'DELETE FROM support_tickets WHERE ticket_id = ?';
    db.query(sql, [ticketId], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Ticket not found' });
        }
        res.json({ message: 'Ticket deleted successfully' });
    });
});

// Admin Signup
app.post("/admin/signup", upload.single("admin_profile_photo"), (req, res) => {
    const { admin_email, admin_name, admin_password } = req.body;
    const admin_profile_photo = req.file ? req.file.filename : null;

    const sql = "INSERT INTO admins (admin_email, admin_name, admin_password, admin_profile_photo) VALUES (?, ?, ?, ?)";
    db.query(sql, [admin_email, admin_name, admin_password, admin_profile_photo], (err, result) => {
        if (err) {
            console.error("Signup error:", err.message);
            return res.status(400).json({ error: err.message });
        }
        console.log("Admin registered:", { id: result.insertId, admin_email });
        res.json({ message: "Admin Registered Successfully" });
    });
});

// Admin Login
app.post("/admin/login", (req, res) => {
    const { admin_email, admin_password } = req.body;
    if (!admin_email || !admin_password) {
        return res.status(400).json({ error: "Email and password are required" });
    }
    const sql = "SELECT * FROM admins WHERE admin_email = ? AND admin_password = ?";
    db.query(sql, [admin_email, admin_password], (err, results) => {
        if (err) return res.status(500).json({ error: "Server error: " + err.message });
        if (results.length === 0) return res.status(401).json({ error: "Invalid Email or Password" });
        console.log("Login successful:", { admin_email });
        res.json({ 
            message: "Login Successful", 
            profile: results[0].admin_profile_photo,
            adminName: results[0].admin_name
        });
    });
});

// Forgot Password
app.post("/admin/forgot-password", (req, res) => {
    const { admin_email, newPassword } = req.body;

    if (!admin_email || !newPassword) {
        return res.status(400).json({ error: "Email and new password are required" });
    }

    const sql = "UPDATE admins SET admin_password = ? WHERE admin_email = ?";
    db.query(sql, [newPassword, admin_email], (err, result) => {
        if (err) {
            console.error("Forgot password error:", err.message);
            return res.status(500).json({ error: "Server error: " + err.message });
        }
        if (result.affectedRows === 0) {
            console.error("User not found:", { admin_email });
            return res.status(404).json({ error: "User not found" });
        }
        console.log("Password updated:", { admin_email });
        res.json({ message: "Password Updated Successfully" });
    });
});
//-------------------------- Staff side ------------------
app.post('/signup', (req, res) => {
    const { name, email, password } = req.body;
    db.query('INSERT INTO staff (name, email, password) VALUES (?, ?, ?)', [name, email, password], (err) => {
        if (err) return res.json({ success: false, message: 'Error registering user' });
        res.json({ success: true, message: 'User registered successfully' });
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM staff WHERE email = ? AND password = ?', [email, password], (err, results) => {
        if (err || results.length === 0) return res.json({ success: false, message: 'Invalid credentials' });
        res.json({ success: true, message: 'Login successful' });
    });
});

app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    db.query('SELECT * FROM staff WHERE email = ?', [email], (err, results) => {
        if (err || results.length === 0) return res.json({ success: false, message: 'Email not found' });
        res.json({ success: true, message: 'Password reset link sent to email' });
    });
});
// Start Server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});