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
app.use(express.static(".")); // Serve static files (index.html, trace.html)

// File Upload Configuration
const storage = multer.diskStorage({
    destination: "uploads/",
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

// Auto-update token on refresh
oAuth2Client.on("tokens", (tokens) => {
    if (tokens.refresh_token) {
        fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens));
        console.log("Token refreshed and saved to", TOKEN_PATH);
    }
    oAuth2Client.setCredentials(tokens);
});

// Initialize Gmail API
const gmail = google.gmail({ version: "v1", auth: oAuth2Client });

// Email Sending Function
async function sendTicketEmail(to, ticketData) {
    const sender = "your_email@gmail.com"; // Replace with your Gmail address
    const subject = "Your Helpdesk Support Ticket Details";
    const message = `
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <h2 style="color: #00bcd4;">Your Support Ticket</h2>
            <p>Thank you for submitting your ticket! Below are the details:</p>
            <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 20px auto;">
                <p><strong>Issue Type:</strong> ${ticketData.issue_type}</p>
                <p><strong>Name:</strong> ${ticketData.name}</p>
                <p><strong>Email:</strong> ${ticketData.email}</p>
                <p><strong>Priority:</strong> ${ticketData.priority}</p>
                <p><strong>Branch Code:</strong> ${ticketData.branchcode}</p>
                <p><strong>Address:</strong> ${ticketData.address}</p>
                <p><strong>User Code (Bank Code):</strong> ${ticketData.user_code}</p>
                <p><strong>Subject:</strong> ${ticketData.subject}</p>
                <p><strong>Message:</strong> ${ticketData.message}</p>
                ${ticketData.attachment1 ? `<p><strong>Attachment:</strong> ${ticketData.attachment1}</p>` : ""}
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

// Handle Form Submission
app.post("/submit-ticket", upload.single("attachment1"), async (req, res) => {
    const {
        issue_type,
        name,
        email,
        priority,
        branchcode,
        address,
        user_code,
        subject,
        message,
    } = req.body;

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

    const values = [
        issue_type,
        name,
        email,
        priority,
        branchcodeInt,
        address,
        user_code,
        subject,
        message,
        attachment1,
    ];

    try {
        await initializeAuth();

        const insertResult = await new Promise((resolve, reject) => {
            db.query(sql, values, (err, result) => {
                if (err) {
                    console.error("Database insertion error:", err.message);
                    reject(err);
                } else {
                    resolve(result);
                }
            });
        });

        const ticket_id = insertResult.insertId;
        const ticketData = {
            issue_type,
            name,
            email,
            priority,
            branchcode: branchcodeInt,
            address,
            user_code,
            subject,
            message,
            attachment1,
            ticket_id,
            submission_date: new Date(), // Use current date for email
        };

        await sendTicketEmail(email, ticketData);
        res.json({ message: "Ticket submitted and email sent successfully!", ticket_id });
    } catch (error) {
        console.error("Error in submission process:", error.message);
        res.status(500).json({ message: "Error submitting ticket or sending email: " + error.message });
    }
});

// New Endpoint: Track Ticket
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
        res.json(results[0]); // Return the first (and only) matching ticket
    });
});
app.post("/login", (req, res) => {
    const { email, password } = req.body;
    const sql = "SELECT * FROM admins WHERE email = ? AND password = ?";

    db.query(sql, [email, password], (err, result) => {
        if (err) throw err;
        if (result.length > 0) {
            res.json({ 
                message: "Login Successful!", 
                redirect: "admin-dashboard.html"  // Ensure this file exists in the same directory
            });
        } else {
            res.status(401).json({ error: "Invalid email or password!" });
        }
    });
});


// API to fetch all support tickets
app.get("/api/tickets", (req, res) => {
    const query = "SELECT * FROM support_tickets ORDER BY datetime DESC";
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});
// Start Server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});