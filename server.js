const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const app = express();

app.use(bodyParser.json());
app.use(cors());

const dbURI =
  "mongodb+srv://LeonAli:t0dqsPodJVqk61DK@cluster0.pmffn8w.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

mongoose
  .connect(dbURI, { useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected..."))
  .catch((err) => console.error(err));

const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  password: String,
  gender: String,
  title: String,
  street: String,
  no: String,
  zipCode: String,
  city: String,
  country: String,
  political: String,
  usTax: String,
  dateOfBirth: String,
  placeOfBirth: String,
  nationality: String,
  phone: String,
  token: String, // Added token field
});

const User = mongoose.model("User", userSchema);

const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).send("Token is required");

  try {
    const decoded = jwt.verify(token.split(" ")[1], "your_jwt_secret");
    req.userId = decoded.id;
    next();
  } catch (err) {
    res.status(401).send("Invalid token");
  }
};

app.post("/signup", async (req, res) => {
  const {
    firstName,
    lastName,
    email,
    password,
    confirmPassword,
    gender,
    title,
    street,
    no,
    zipCode,
    city,
    country,
    political,
    usTax,
    dateOfBirth,
    placeOfBirth,
    nationality,
    phone,
  } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).send("Passwords do not match");
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({
    firstName,
    lastName,
    email,
    password: hashedPassword,
    gender,
    title,
    street,
    no,
    zipCode,
    city,
    country,
    political,
    usTax,
    dateOfBirth,
    placeOfBirth,
    nationality,
    phone,
  });

  try {
    await newUser.save();
    res.status(201).send("User created successfully");
  } catch (err) {
    if (err.code === 11000) {
      res.status(400).send("Email already exists");
    } else {
      console.error("Error creating user:", err);
      res.status(500).send("Error creating user");
    }
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).send("Invalid credentials");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send("Invalid credentials");
    }

    const token = jwt.sign({ id: user._id }, "your_jwt_secret", {
      expiresIn: "1h",
    });
    user.token = token;
    await user.save();

    res.status(200).json({ message: "Login successful", token });
  } catch (err) {
    console.error("Error logging in:", err);
    res.status(500).send("Error logging in");
  }
});

app.get("/user", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).send("User not found");
    res.status(200).json(user);
  } catch (err) {
    res.status(500).send("Error fetching user data");
  }
});
app.post("/logout", (req, res) => {
  // Invalidate the token or handle session cleanup if needed
  res.status(200).send("Logout successful");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
