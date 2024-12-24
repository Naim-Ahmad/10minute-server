const express = require("express");
const { default: mongoose } = require("mongoose");
const jwt = require("jsonwebtoken");
const User = require("./models/UserModel");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const app = express();
require("dotenv").config();
const port = 3000;

// Middleware to parse JSON request bodies
app.use([express.json(), cors()]);

app.get("/test", (req, res) => {
  res.json({ message: "server is ok" });
});

// database connection
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    dbName: "10minuteDB",
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error.message);
  });

// authentication system
app.get("/auth/check/:identifier", async (req, res) => {
  const { identifier } = req.params;

  // Regular expressions for validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const phoneRegex = /^(\+88)?01[3-9]\d{8}$/;

  // Check if the identifier is valid (email or phone)
  if (
    !identifier ||
    (!emailRegex.test(identifier) && !phoneRegex.test(identifier))
  ) {
    return res.status(400).json({
      message: "Please provide a valid email or phone number!",
    });
  }

  try {
    // Determine whether it's an email or phone and check the database
    const userExists = await User.exists({ identifier });

    return res.status(200).json({
      message: "Success",
      userExists: !!userExists,
    });
  } catch (error) {
    return res.status(500).json({
      message: "An error occurred while checking the identifier.",
      error: error.message,
    });
  }
});

app.post("/auth/register", async (req, res) => {
  const { identifier, password } = req.body;

  // Regular expressions for validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const phoneRegex = /^(\+88)?01[3-9]\d{8}$/;
  console.log(identifier, password);
  // Validate identifier (email or phone) and password
  if (
    !identifier ||
    (!emailRegex.test(identifier) && !phoneRegex.test(identifier))
  ) {
    return res.status(400).json({
      message:
        "Invalid identifier! Please provide a valid email or phone number.",
    });
  }

  if (!password || password.length < 6) {
    return res.status(400).json({
      message: "Password must be at least 6 characters long.",
    });
  }

  try {
    const isEmail = emailRegex.test(identifier);
    // Check if user already exists
    const existingUser = await User.findOne({ identifier });
    if (existingUser) {
      return res.status(409).json({
        message: isEmail
          ? "Email is already registered!"
          : "Phone number is already registered!",
      });
    }

    // Create new user
    const newUser = new User({
      identifier,
      password,
    });

    console.log(newUser);

    await newUser.save();
    return res.status(201).json({
      message: "User registered successfully!",
      user: {
        id: newUser._id,
        identifier: newUser.identifier,
      },
    });
  } catch (error) {
    console.error("Error during registration:", error);
    return res.status(500).json({
      message: "An error occurred during registration.",
      error: error.message,
    });
  }
});

app.post("/auth/login", async (req, res) => {
  const { identifier, password } = req.body;

  // Regular expressions for validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const phoneRegex = /^(\+88)?01[3-9]\d{8}$/;

  // Validate identifier (email or phone) and password
  if (
    !identifier ||
    (!emailRegex.test(identifier) && !phoneRegex.test(identifier))
  ) {
    return res.status(400).json({
      message: "Please provide a valid email or phone number.",
    });
  }

  if (!password) {
    return res.status(400).json({
      message: "Password is required.",
    });
  }

  try {
    // Find user in the database
    const user = await User.findOne({ identifier });
    if (!user) {
      return res.status(404).json({
        message: "User not found! Please check your credentials.",
      });
    }

    // Compare password
    const isPasswordValid = await bcrypt.compare(password, user?.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        message: "Invalid password! Please try again.",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        id: user._id,
        identifier: user.identifier,
      },
      process.env.JWT_SECRET || "hassan563488",
      { expiresIn: "7d" }
    );

    return res.status(200).json({
      message: "Login successful!",
      token,
      user: {
        id: user._id,
        identifier: user.identifier,
      },
    });
  } catch (error) {
    console.error("Error during login:", error);
    return res.status(500).json({
      message: "An error occurred during login.",
      error: error.message,
    });
  }
});

app.listen(port, () =>
  console.log(`Server listening on http://localhost:${port}`)
);
