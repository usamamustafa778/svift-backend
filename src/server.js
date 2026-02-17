require('dotenv').config();

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const User = require('./models/User');
const { sendOtpEmail } = require('./lib/email');

const app = express();

app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/svift';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

async function startServer() {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error('MongoDB connection error', err);
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`Auth API listening on port ${PORT}`);
  });
}

startServer();

function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function setUserOtp(user, label) {
  const verificationCode = generateVerificationCode();
  user.verificationCode = verificationCode;
  user.verificationCodeExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
  await user.save();

  const { sent, error } = await sendOtpEmail(user.email, verificationCode, label);
  if (sent) {
    console.log(`${label} OTP sent to ${user.email}`);
  } else {
    console.warn(`${label} OTP email failed for ${user.email}:`, error || 'not configured');
    console.log(`Fallback OTP for ${user.email}: ${verificationCode}`);
  }

  return verificationCode;
}

function signToken(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '7d' });
}

app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Svift auth API' });
});

// Step 1: start signup with email only, send OTP
app.post('/auth/signup/start', async (req, res) => {
  try {
    const rawEmail = req.body?.email;
    if (!rawEmail || typeof rawEmail !== 'string') {
      return res.status(400).json({ message: 'Email is required' });
    }
    const email = rawEmail.trim().toLowerCase();

    let user = await User.findOne({ email });

    if (user && user.passwordHash && user.isVerified) {
      return res.status(409).json({ message: 'User already exists' });
    }

    if (!user) {
      user = await User.create({
        email,
        isVerified: false,
      });
    }

    await setUserOtp(user, 'Signup');

    return res.status(201).json({
      message: 'User created. Verify your email with the code sent.',
      email: user.email,
    });
  } catch (err) {
    console.error(err);
    if (err.name === 'ValidationError') {
      return res.status(400).json({ message: err.message || 'Validation failed' });
    }
    if (err.code === 11000) {
      return res.status(409).json({ message: 'User already exists' });
    }
    return res.status(500).json({ message: 'Server error' });
  }
});

// Step 2: verify email with OTP during signup
app.post('/auth/verify-email', async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ message: 'Email and code are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const now = new Date();
    if (
      !user.verificationCode ||
      user.verificationCode !== code ||
      !user.verificationCodeExpiresAt ||
      user.verificationCodeExpiresAt < now
    ) {
      return res.status(400).json({ message: 'Invalid or expired code' });
    }

    user.isVerified = true;
    user.verificationCode = undefined;
    user.verificationCodeExpiresAt = undefined;
    await user.save();

    return res.json({
      message: 'Email verified. You can now create a password.',
      email: user.email,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (!user.passwordHash) {
      return res.status(400).json({ message: 'Account setup incomplete. Please finish signup.' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      await setUserOtp(user, 'Login');

      return res.status(200).json({
        message: 'Email not verified. Verification code sent.',
        requiresVerification: true,
        email: user.email,
      });
    }

    const token = signToken(user.id);

    return res.json({
      message: 'Login successful',
      token,
      email: user.email,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

app.post('/auth/login/verify', async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ message: 'Email and code are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const now = new Date();
    if (
      !user.verificationCode ||
      user.verificationCode !== code ||
      !user.verificationCodeExpiresAt ||
      user.verificationCodeExpiresAt < now
    ) {
      return res.status(400).json({ message: 'Invalid or expired code' });
    }

    user.isVerified = true;
    user.verificationCode = undefined;
    user.verificationCodeExpiresAt = undefined;
    await user.save();

    const token = signToken(user.id);

    return res.json({
      message: 'Login verified',
      token,
      email: user.email,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Step 3: complete signup by setting password after email OTP verification
app.post('/auth/signup/complete', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.isVerified) {
      return res.status(400).json({ message: 'Email not verified yet' });
    }

    if (user.passwordHash) {
      return res.status(400).json({ message: 'Password already set for this account' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    user.passwordHash = passwordHash;
    await user.save();

    const token = signToken(user.id);

    return res.json({
      message: 'Account created successfully',
      token,
      email: user.email,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Generic OTP resend endpoint – can be used from both signup and login flows
app.post('/auth/otp/resend', async (req, res) => {
  try {
    const { email, context = 'Generic' } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    await setUserOtp(user, `${context} resend`);

    return res.json({
      message: 'A new verification code has been sent.',
      email: user.email,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});
