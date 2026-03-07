require('dotenv').config();

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');

const User = require('./models/User');
const { sendOtpEmail } = require('./lib/email');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Use JPEG, PNG, WebP or GIF.'));
    }
  },
});

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

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.sub;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
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
      name: user.name || '',
      profilePhotoUrl: user.profilePhotoUrl || null,
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
      name: user.name || '',
      profilePhotoUrl: user.profilePhotoUrl || null,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Real Google login – verifies the OAuth access token with Google's userinfo API
app.post('/auth/login/google', async (req, res) => {
  try {
    const { accessToken } = req.body;
    if (!accessToken) {
      return res.status(400).json({ message: 'Google access token is required' });
    }

    // Use OpenID Connect userinfo (more reliable for name) – fallback to oauth2/v3
    let googleUser;
    let googleRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!googleRes.ok) {
      googleRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
    }
    if (!googleRes.ok) {
      return res.status(401).json({ message: 'Invalid or expired Google token' });
    }

    googleUser = await googleRes.json();
    const { sub: googleId, email, picture: googlePicture } = googleUser;

    if (!email) {
      return res.status(400).json({ message: 'Google account has no email address' });
    }

    // Use Google name: name → given_name + family_name → email prefix
    const name = (googleUser.name && String(googleUser.name).trim())
      || [googleUser.given_name, googleUser.family_name].filter(Boolean).join(' ').trim()
      || email.split('@')[0];

    // Find existing user by googleId or email, then link / create
    let user = await User.findOne({ $or: [{ googleId }, { email }] });
    if (!user) {
      // New user: store Google photo as profilePhotoUrl (first time only)
      user = await User.create({
        email,
        name,
        googleId,
        isVerified: true,
        profilePhotoUrl: googlePicture && String(googlePicture).trim() ? googlePicture : null,
      });
    } else {
      let changed = false;
      if (!user.googleId) { user.googleId = googleId; changed = true; }
      if (!user.isVerified) { user.isVerified = true; changed = true; }
      if (user.name !== name) { user.name = name; changed = true; }
      // Use Google photo only if user has no profilePhotoUrl yet (first time; custom upload overwrites this)
      if (!user.profilePhotoUrl && googlePicture && String(googlePicture).trim()) {
        user.profilePhotoUrl = googlePicture;
        changed = true;
      }
      if (changed) await user.save();
    }

    const token = signToken(user.id);
    return res.json({
      message: 'Google login successful',
      token,
      email: user.email,
      name: user.name || name,
      profilePhotoUrl: user.profilePhotoUrl || null,
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
      name: user.name || '',
      profilePhotoUrl: user.profilePhotoUrl || null,
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

// Get current user profile (requires auth)
app.get('/users/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('email name profilePhotoUrl');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    return res.json({
      email: user.email,
      name: user.name || '',
      profilePhotoUrl: user.profilePhotoUrl || null,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Upload profile photo (requires auth)
app.patch('/users/me/profile-photo', authMiddleware, upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No photo file provided' });
    }

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: 'svift-profile-photos',
          transformation: [
            { width: 400, height: 400, crop: 'fill', gravity: 'face' },
          ],
        },
        (err, result) => (err ? reject(err) : resolve(result))
      );
      uploadStream.end(req.file.buffer);
    });

    user.profilePhotoUrl = result.secure_url;
    await user.save();

    return res.json({ profilePhotoUrl: user.profilePhotoUrl });
  } catch (err) {
    console.error('Profile photo upload error:', err);
    if (err.message && err.message.includes('Invalid file type')) {
      return res.status(400).json({ message: err.message });
    }
    return res.status(500).json({ message: 'Failed to upload profile photo' });
  }
});
