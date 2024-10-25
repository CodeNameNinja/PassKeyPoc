const express = require('express');
const cors = require('cors'); // Import cors
const bodyParser = require('body-parser');
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const {v4: uuidv4} = require('uuid');
const base64url = require('base64url');

if (typeof globalThis.crypto === 'undefined') {
    // Import Node's crypto module and set globalThis.crypto to crypto.webcrypto
    globalThis.crypto = require('crypto').webcrypto;
}

// Create a simple in-memory store for users (this is just for PoC, not for production)
const users = new Map();

const app = express();

app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cors());
const PORT = 3000;


app.get('/generate-registration-options', async (req, res) => {
    const userId = uuidv4(); // Create a new user ID for this registration
    const user = {
        id: userId,
        username: `user-${userId}`,
        devices: [], // Store user devices (public keys, etc.)
    };

    users.set(userId, user); // Store the user in our in-memory "database"

    // const encodedUserID = new TextEncoder().encode(user.id);

    // Generate registration options using @simplewebauthn/server
    const options = await generateRegistrationOptions({
        rpName: 'Passkey PoC',
        rpID: 'localhost', // For local testing; use your domain in production
        userID: base64url.toBuffer(user.id),
        userName: user.username,
        attestationType: 'direct', // Type of attestation (for PoC, use 'direct')
    });

    // Save challenge in user object for verification later
    user.currentChallenge = options.challenge;

    // Base64URL-encode challenge and user ID
    options.challenge = base64url.encode(options.challenge);
    options.user.id = base64url.encode(options.user.id);

    // Base64URL-encode any excludeCredentials IDs if present
    if (options.excludeCredentials) {
        options.excludeCredentials = options.excludeCredentials.map(cred => ({
            ...cred,
            id: base64url.encode(cred.id),
        }));
    }

    res.json(options);
});


app.post('/verify-registration', async (req, res) => {
    let {userId, registrationResponse} = req.body;
    const decodedUserId = base64url.decode(userId);

    // Look up the user using the decoded ID
    const user = users.get(decodedUserId);

    if (!user) {
        return res.status(400).json({error: 'User not found'});
    }

    const clientData = JSON.parse(Buffer.from(registrationResponse.response.clientDataJSON, 'base64').toString('utf8'));
    // decode clientData.challenge
    const decodedChallenge = base64url.decode(clientData.challenge);
    const encodedChallenge = base64url.encode(user.currentChallenge);

    console.log("Decoded challenge:", decodedChallenge);
    console.log("Original server challenge:", user.currentChallenge);

    try {
        // Verify the registration response
        const verification = await verifyRegistrationResponse({
            response: registrationResponse,
            expectedChallenge: encodedChallenge,
            expectedOrigin: 'http://localhost:63342', // The origin you expect; update for production
            expectedRPID: 'localhost', // For local testing
        });

        if (verification.verified) {
            // Save the credential public key info to user devices
            user.devices.push(verification.registrationInfo);
            delete user.currentChallenge; // Clear the challenge

            res.json({success: true});
        } else {
            res.status(400).json({success: false, error: 'Verification failed'});
        }
    } catch (error) {
        res.status(500).json({success: false, error: error.message});
    }
});

app.get('/generate-authentication-options', async (req, res) => {
    const userId = base64url.decode(req.query.userId) // Assume the user ID is passed as a query parameter

    const user = users.get(userId);

    if (!user) {
        return res.status(400).json({error: 'User not found'});
    }

    const options = await generateAuthenticationOptions({
        allowCredentials: user.devices.map(device => ({
            id: device.credential.id, // Buffer containing credential ID
            type: 'public-key',
            transports: ['internal'], // Adjust if needed
        })),
        userVerification: 'preferred',
        rpID: 'localhost', // Replace with your domain in production
    });

    // Save challenge for verification
    user.currentChallenge = options.challenge;

    res.json(options);
});

app.post('/verify-authentication', async (req, res) => {
    const {userId, authenticationResponse} = req.body;
    const user = users.get(base64url.decode(userId));

    if (!user) {
        return res.status(400).json({error: 'User not found'});
    }

    const expectedChallenge = user.currentChallenge;

    const authenticator = user.devices.find(device =>
        device.credential.id === authenticationResponse.rawId
    );

    try {
        const verification = await verifyAuthenticationResponse({
                response: authenticationResponse,
                expectedChallenge: `${expectedChallenge}`,
                expectedRPID: 'localhost', // Replace with your domain
                expectedOrigin: 'http://localhost:63342', // Replace with your web page's origin
                credential: authenticator.credential,
                requireUserVerification:
                    true,
            })
        ;

        if (verification.verified) {
            // Authentication successful
            res.json({success: true});
        } else {
            res.status(400).json({success: false, error: 'Authentication failed'});
        }
    } catch (error) {
        res.status(500).json({success: false, error: error.message});
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});