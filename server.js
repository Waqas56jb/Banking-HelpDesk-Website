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
    password: "1234", // Your MySQL password
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
async function sendEmail(to, subject, message) {
    const sender = "your_email@gmail.com"; // Replace with your Gmail address
    const emailContent = [
        `From: ${sender}`,
        `To: ${to}`,
        `Subject: ${subject}`,
        "MIME-Version: 1.0",
        "Content-Type: text/html; charset=utf-8",
        "",
        message,
    ].join("\n");

    const encodedMessage = Buffer.from(emailContent)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

    try {
        await initializeAuth();
        const response = await gmail.users.messages.send({
            userId: "me",
            requestBody: { raw: encodedMessage },
        });
        console.log(`Email sent to ${to}: ${response.data.id}`);
        return response;
    } catch (error) {
        console.error("Error sending email:", error.message);
        throw error;
    }
}

// Existing Ticket Submission Endpoint (unchanged)
async function sendTicketEmail(to, ticketData) {
    const sender = "your_email@gmail.com";
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
            issue_type, name, email, priority, branchcode, address, user_code, subject, message, attachment1, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Under Working')
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

// Existing Endpoints (unchanged)
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

app.get("/api/tickets", (req, res) => {
    const query = `
        SELECT ticket_id, issue_type, name, email, priority, branchcode, address, 
               user_code, subject, message, attachment1, submission_date, status 
        FROM support_tickets 
        ORDER BY submission_date DESC
    `;
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.delete('/api/tickets/:id', (req, res) => {
    const ticketId = req.params.id;
    const sql = 'DELETE FROM support_tickets WHERE ticket_id = ?';
    db.query(sql, [ticketId], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Ticket not found' });
        res.json({ message: 'Ticket deleted successfully' });
    });
});

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
            adminName: results[0].admin_name,
            adminEmail: results[0].admin_email
        });
    });
});

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
        res.json({ success: true, message: 'Login successful', staffEmail: results[0].email });
    });
});

app.post('/verify-email', (req, res) => {
    const { email } = req.body;
    db.query('SELECT * FROM staff WHERE email = ?', [email], (err, results) => {
        if (err || results.length === 0) return res.json({ success: false, message: 'Email not found' });
        res.json({ success: true, message: 'Email verified' });
    });
});

app.post('/reset-password', (req, res) => {
    const { email, newPassword } = req.body;
    db.query('UPDATE staff SET password = ? WHERE email = ?', [newPassword, email], (err) => {
        if (err) return res.json({ success: false, message: 'Error updating password' });
        res.json({ success: true, message: 'Password updated successfully' });
    });
});

app.post('/admin/forgetpassword/api', (req, res) => {
    const { admin_email } = req.body;

    db.query('SELECT * FROM admins WHERE admin_email = ?', [admin_email], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (results.length === 0) return res.status(404).json({ message: 'Admin email not found' });

        res.json({ message: 'Email verified. You can reset your password.' });
    });
});

app.post('/admin/reset', (req, res) => {
    const { admin_email, newPassword, confirmPassword } = req.body;

    if (!admin_email || !newPassword || !confirmPassword) {
        return res.status(400).json({ message: 'Missing required fields' });
    }

    if (newPassword !== confirmPassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
    }

    db.query('UPDATE admins SET admin_password = ? WHERE admin_email = ?', 
    [newPassword, admin_email], (err) => {
        if (err) return res.status(500).json({ message: 'Error updating password' });
        res.json({ message: 'Password changed successfully' });
    });
});

app.post("/api/send-announcement", async (req, res) => {
    const { emails, subject, message } = req.body;
    if (!emails || !subject || !message) {
        return res.status(400).json({ message: "Emails, subject, and message are required." });
    }

    try {
        const emailArray = [...new Set(Array.isArray(emails) ? emails : [emails])];
        const promises = emailArray.map(email => sendEmail(email, subject, message));
        await Promise.all(promises);
        res.json({ message: "Announcements sent successfully!" });
    } catch (error) {
        console.error("Error in send-announcement endpoint:", error.message);
        res.status(500).json({ message: "Error sending announcements: " + error.message });
    }
});

app.delete("/api/tickets/all", (req, res) => {
    const sql = "DELETE FROM support_tickets";
    db.query(sql, (err, result) => {
        if (err) {
            console.error("Error deleting all tickets:", err.message);
            return res.status(500).json({ error: "Database error: " + err.message });
        }
        console.log(`Deleted ${result.affectedRows} tickets`);
        res.json({ message: "All tickets deleted successfully", deletedCount: result.affectedRows });
    });
});

app.get('/banker/signup', (req, res) => {
    res.sendFile(__dirname + '/public/banker_signup.html');
});

app.post('/banker/signup', (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    db.query('SELECT * FROM bankers WHERE username = ? OR email = ?', [username, email], (err, rows) => {
        if (err) return res.status(500).json({ success: false, message: 'Database error' });
        if (rows.length > 0) return res.status(400).json({ success: false, message: 'Username or email already exists' });
        db.query('INSERT INTO bankers (username, email, password) VALUES (?, ?, ?)', [username, email, password], (err) => {
            if (err) return res.status(500).json({ success: false, message: 'Error creating banker account' });
            res.json({ success: true, message: 'Banker account created successfully' });
        });
    });
});

app.get('/banker/login', (req, res) => {
    res.sendFile(__dirname + '/public/banker_login.html');
});

app.post('/banker/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required' });
    }
    db.query('SELECT * FROM bankers WHERE email = ? AND password = ?', [email, password], (err, rows) => {
        if (err) return res.status(500).json({ success: false, message: 'Database error' });
        if (rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid email or password' });
        res.json({ success: true, message: 'Login successful', bankerEmail: rows[0].email });
    });
});

app.get('/banker/forgetpassword', (req, res) => {
    res.sendFile(__dirname + '/public/banker_forgetpassword.html');
});

app.post('/banker/checkemail', (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'Email is required' });
    db.query('SELECT * FROM bankers WHERE email = ?', [email], (err, rows) => {
        if (err) return res.status(500).json({ success: false, message: 'Database error' });
        if (rows.length === 0) return res.status(404).json({ success: false, message: 'Email not found' });
        res.json({ success: true, message: 'Email exists' });
    });
});

app.post('/banker/forgetpassword', (req, res) => {
    const { email, newpassword, confirmpassword } = req.body;
    if (!email || !newpassword || !confirmpassword) return res.status(400).json({ success: false, message: 'All fields are required' });
    if (newpassword !== confirmpassword) return res.status(400).json({ success: false, message: 'Passwords do not match' });
    db.query('SELECT * FROM bankers WHERE email = ?', [email], (err, rows) => {
        if (err) return res.status(500).json({ success: false, message: 'Database error' });
        if (rows.length === 0) return res.status(404).json({ success: false, message: 'Email not found' });
        db.query('UPDATE bankers SET password = ? WHERE email = ?', [newpassword, email], (err) => {
            if (err) return res.status(500).json({ success: false, message: 'Error updating password' });
            res.json({ success: true, message: 'Password updated successfully' });
        });
    });
});

app.put('/api/tickets/:ticket_id/resolve', (req, res) => {
    const ticketId = req.params.ticket_id;
    const sql = 'UPDATE support_tickets SET status = "Request Resolved" WHERE ticket_id = ?';
    db.query(sql, [ticketId], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error: ' + err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Ticket not found' });
        res.json({ message: 'Ticket resolved successfully' });
    });
});

app.get('/api/staff', (req, res) => {
    db.query('SELECT name, email, password FROM staff', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.get('/api/bankers', (req, res) => {
    db.query('SELECT username, email, password FROM bankers', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.get('/api/admins', (req, res) => {
    db.query('SELECT admin_name, admin_email, admin_password FROM admins', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// New Endpoints for Communication
// ... (Your existing server.js code remains unchanged up to this point)

// New Endpoints for Messaging

// Fetch all users (for recipient selection)
app.get('/api/users', (req, res) => {
    const staffQuery = 'SELECT email, "staff" AS role FROM staff';
    const bankersQuery = 'SELECT email, "banker" AS role FROM bankers';
    const adminsQuery = 'SELECT admin_email AS email, "admin" AS role FROM admins';
    const query = `${staffQuery} UNION ${bankersQuery} UNION ${adminsQuery}`;
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// Send Communication Message
app.post('/api/send-message', async (req, res) => {
    const { sender_email, recipient_emails, ticket_id, subject, message_text } = req.body;
    if (!sender_email || !recipient_emails || !subject || !message_text) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        await initializeAuth();

        // Fetch ticket details if ticket_id is provided
        let ticket = null;
        if (ticket_id) {
            const ticketQuery = 'SELECT * FROM support_tickets WHERE ticket_id = ?';
            ticket = await new Promise((resolve, reject) => {
                db.query(ticketQuery, [ticket_id], (err, results) => {
                    if (err) reject(err);
                    if (results.length === 0) reject(new Error('Ticket not found'));
                    resolve(results[0]);
                });
            });
        }

        const ticketCard = ticket ? `
            <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 20px auto;">
                <h3 style="color: #007bff;">Ticket #${ticket.ticket_id}</h3>
                <p><strong>Issue Type:</strong> ${ticket.issue_type}</p>
                <p><strong>Name:</strong> ${ticket.name}</p>
                <p><strong>Email:</strong> ${ticket.email}</p>
                <p><strong>Priority:</strong> ${ticket.priority}</p>
                <p><strong>Branch Code:</strong> ${ticket.branchcode}</p>
                <p><strong>User Code:</strong> ${ticket.user_code}</p>
                <p><strong>Subject:</strong> ${ticket.subject}</p>
                <p><strong>Message:</strong> ${ticket.message}</p>
                ${ticket.attachment1 ? `<p><strong>Attachment:</strong> <a href="http://localhost:3000/uploads/${ticket.attachment1}">${ticket.attachment1}</a></p>` : ""}
                <p><strong>Submission Date:</strong> ${new Date(ticket.submission_date).toLocaleString()}</p>
                <p><strong>Status:</strong> ${ticket.status || 'Under Working'}</p>
            </div>
        ` : '';

        const fullMessage = `
            <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
                <h2 style="color: #007bff;">Message from ${sender_email}</h2>
                <p>${message_text}</p>
                ${ticketCard}
            </body>
            </html>
        `;

        const recipientArray = Array.isArray(recipient_emails) ? recipient_emails : [recipient_emails];
        const emailPromises = recipientArray.map(email => sendEmail(email, subject, fullMessage));
        await Promise.all(emailPromises);

        // Save to communication history
        const historyQuery = 'INSERT INTO communication_history (sender_email, recipient_email, ticket_id, subject, message_text, sent_at) VALUES ?';
        const historyValues = recipientArray.map(recipient => [sender_email, recipient, ticket_id || null, subject, message_text, new Date()]);
        await new Promise((resolve, reject) => {
            db.query(historyQuery, [historyValues], (err, result) => {
                if (err) reject(err);
                resolve(result);
            });
        });

        res.json({ message: 'Message sent successfully!' });
    } catch (error) {
        console.error('Error sending message:', error.message);
        res.status(500).json({ message: 'Error sending message: ' + error.message });
    }
});

// Fetch Communication History
app.get('/api/message-history', (req, res) => {
    const { email } = req.query;
    if (!email) return res.status(400).json({ message: 'Email is required' });
    const query = `
        SELECT * FROM communication_history 
        WHERE sender_email = ? OR recipient_email = ?
        ORDER BY sent_at DESC
    `;
    db.query(query, [email, email], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// New Endpoint for Records Page
app.get('/api/records', (req, res) => {
    const staffQuery = 'SELECT name, email, password FROM staff';
    const bankersQuery = 'SELECT username, email, password FROM bankers';
    const adminsQuery = 'SELECT admin_name, admin_email, admin_password FROM admins';

    Promise.all([
        new Promise((resolve, reject) => {
            db.query(staffQuery, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        }),
        new Promise((resolve, reject) => {
            db.query(bankersQuery, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        }),
        new Promise((resolve, reject) => {
            db.query(adminsQuery, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        })
    ])
    .then(([staff, bankers, admins]) => {
        res.json({ staff, bankers, admins });
    })
    .catch(err => {
        console.error('Error fetching records:', err.message);
        res.status(500).json({ error: 'Database error: ' + err.message });
    });
});
// New Endpoints for Deleting Accounts
app.delete('/api/staff/:email', (req, res) => {
    const email = req.params.email;
    db.query('DELETE FROM staff WHERE email = ?', [email], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error: ' + err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Staff not found' });
        res.json({ message: 'Staff account deleted successfully' });
    });
});

app.delete('/api/bankers/:email', (req, res) => {
    const email = req.params.email;
    db.query('DELETE FROM bankers WHERE email = ?', [email], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error: ' + err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Banker not found' });
        res.json({ message: 'Banker account deleted successfully' });
    });
});

app.delete('/api/admins/:email', (req, res) => {
    const email = req.params.email;
    db.query('DELETE FROM admins WHERE admin_email = ?', [email], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error: ' + err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Admin not found' });
        res.json({ message: 'Admin account deleted successfully' });
    });
});
// ... (Rest of your server.js code remains unchanged)
// Start Server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});