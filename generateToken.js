const { google } = require("googleapis");
const { OAuth2Client } = require("google-auth-library");
const fs = require("fs");

try {
    // Load credentials from credentials.json
    const credentials = JSON.parse(fs.readFileSync("credentials.json"));
    const { client_secret, client_id } = credentials.installed;
    const redirect_uris = ["urn:ietf:wg:oauth:2.0:oob"]; // Use OOB flow
    const oAuth2Client = new OAuth2Client(client_id, client_secret, redirect_uris[0]);

    const SCOPES = ["https://www.googleapis.com/auth/gmail.send"];

    // Generate the authorization URL
    const authUrl = oAuth2Client.generateAuthUrl({
        access_type: "offline",
        scope: SCOPES,
    });
    console.log("Authorize this app by visiting this URL:", authUrl);

    // Prompt user for the authorization code
    const readline = require("readline").createInterface({
        input: process.stdin,
        output: process.stdout,
    });

    readline.question("Enter the code from that page here: ", (code) => {
        readline.close();
        oAuth2Client.getToken(code, (err, token) => {
            if (err) {
                console.error("Error retrieving access token:", err.message);
                if (err.response) {
                    console.error("Response data:", err.response.data);
                }
                return;
            }
            fs.writeFileSync("token.json", JSON.stringify(token));
            console.log("Token stored to token.json");
        });
    });
} catch (error) {
    console.error("Error in script execution:", error.message);
}