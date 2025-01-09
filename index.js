const express = require("express");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
require("dotenv").config();
const cors = require("cors");
const jwt = require("jsonwebtoken");

// Create an instance of the Express app
const app = express();
app.use(cors());
app.use(express.json()); // For parsing JSON bodies

// PostgreSQL Pool Setup
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Token is required" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid token" });
  }
};

// User registration route
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required." });
  }

  try {
    const checkUserQuery =
      "SELECT * FROM users WHERE username = $1 OR email = $2";
    const checkUserResult = await pool.query(checkUserQuery, [username, email]);

    if (checkUserResult.rows.length > 0) {
      return res
        .status(400)
        .json({ message: "Username or email already exists." });
    }

    // Hash the password before storing it
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Insert the new user into the database
    const insertUserQuery =
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *";
    const result = await pool.query(insertUserQuery, [
      username,
      email,
      hashedPassword,
    ]);

    const newUser = result.rows[0];
    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
      },
    });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    // Query the database for the user with the provided email
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    // console.log("q:", result)
    if (result.rows.length === 0) {
      // No user found with that email
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = result.rows[0];

    // Compare the provided password with the stored (hashed) password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      // Invalid password
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Password is valid, generate a JWT token (optional)
    const token = jwt.sign(
      { userId: user.id, email: user.email, username: user.username },
      JWT_SECRET_KEY,
      { expiresIn: "1h" } // Token expiration time
    );

    // Send the response with the token
    res.status(200).json({
      message: "Login successful",
      token,
    });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Get user profile and posts
app.get("/profile", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Token is required" });
  }

  try {
    // Verify the token
    const decoded = jwt.verify(token, JWT_SECRET_KEY);
    // console.log(decoded)
    // Get the username and the user's posts
    const { userId, username } = decoded;
    // console.log(userId)
    const userResults = await pool.query(
      "SELECT pfp_url, bio FROM users WHERE id = $1",
      [userId]
    );
    // Get the user's posts
    const postsResult = await pool.query(
      "SELECT * FROM posts WHERE username = $1 ORDER BY post_date DESC",
      [username]
    );
    // console.log(username);
    // console.log(userResults.rows)

    res.status(200).json({
      username: username,
      posts: postsResult.rows,
      profiledata: userResults.rows,
    });
  } catch (error) {
    console.error("Error verifying token or fetching user profile:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/profile/:username", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { username: requestedUsername } = req.params;
  // console.log(requestedUsername)

  if (!token) {
    return res.status(401).json({ message: "Token is required" });
  }

  try {
    // Verify the token
    const decoded = jwt.verify(token, JWT_SECRET_KEY);
    // console.log(decoded)
    // Get the username and the user's posts
    // const {userId, username } = decoded;
    // console.log(userId)
    const userResults = await pool.query(
      "SELECT pfp_url, bio FROM users WHERE username = $1",
      [requestedUsername]
    );
    // Get the user's posts
    const postsResult = await pool.query(
      "SELECT * FROM posts WHERE username = $1 ORDER BY post_date DESC",
      [requestedUsername]
    );
    // console.log(username);
    // console.log(userResults.rows)

    res.status(200).json({
      username: requestedUsername,
      posts: postsResult.rows,
      profiledata: userResults.rows,
    });
  } catch (error) {
    console.error("Error verifying token or fetching user profile:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/invites/generate", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      "INSERT INTO invites (creator_id) VALUES ($1) RETURNING id",
      [req.user.userId]
    );

    const inviteUrl = `${process.env.BASE_URL}/follow.html?/follow_id=${result.rows[0].id}`;
    res.json({ invite_link: inviteUrl });
  } catch (error) {
    console.error("Error generating invite:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/invites/follow/:inviteId", verifyToken, async (req, res) => {
  const { inviteId } = req.params;
  const followerId = req.user.userId;

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Check if invite exists and hasn't been used
    const inviteResult = await client.query(
      "SELECT creator_id, used FROM invites WHERE id = $1",
      [inviteId]
    );

    if (inviteResult.rows.length === 0) {
      throw new Error("Invalid invite");
    }

    if (inviteResult.rows[0].used) {
      throw new Error("Invite already used");
    }

    const creatorId = inviteResult.rows[0].creator_id;

    // Prevent self-following
    if (followerId === creatorId) {
      throw new Error("Cannot follow yourself");
    }

    // Check if already following
    const followCheck = await client.query(
      "SELECT * FROM follows WHERE follower_id = $1 AND following_id = $2",
      [followerId, creatorId]
    );

    if (followCheck.rows.length > 0) {
      throw new Error("Already following this user");
    }

    // Mark invite as used
    await client.query("UPDATE invites SET used = TRUE WHERE id = $1", [
      inviteId,
    ]);

    // Create follow relationship
    await client.query(
      "INSERT INTO follows (follower_id, following_id) VALUES ($1, $2)",
      [followerId, creatorId]
    );

    await client.query("COMMIT");
    res.json({ message: "Successfully followed user" });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Error processing follow request:", error);
    res.status(400).json({ message: error.message });
  } finally {
    client.release();
  }
});

app.get("/api/invites/:inviteId", async (req, res) => {
  const { inviteId } = req.params;
  try {
    const result = await pool.query(
      "SELECT username FROM users WHERE users.id = (SELECT creator_id FROM invites WHERE id = $1)",
      [inviteId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Invite not found" });
    }
    // console.log(result)
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching invite details:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Route to get posts from followed users
app.get("/api/feed", verifyToken, async (req, res) => {
  const followerId = req.user.userId;

  try {
    // Fetch the list of user IDs that the current user follows
    const followedUsersResult = await pool.query(
      "SELECT username FROM users WHERE id = (SELECT following_id FROM follows WHERE follower_id = $1)",
      [followerId]
    );

    if (followedUsersResult.rows.length === 0) {
      return res.status(404).json({ message: "You are not following anyone." });
    }

    const followedUserIds = followedUsersResult.rows.map((row) => row.username);
    console.log(followedUserIds);

    // Fetch the recent posts from the followed users
    const postsResult = await pool.query(
      "SELECT * FROM posts WHERE username = ANY($1) ORDER BY post_date DESC",
      [followedUserIds]
    );
    console.log(postsResult);
    res.json({ posts: postsResult.rows });
  } catch (error) {
    console.error("Error fetching feed:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, 'localhost', () => {
  console.log(`Server is running on port ${PORT}`);
});
