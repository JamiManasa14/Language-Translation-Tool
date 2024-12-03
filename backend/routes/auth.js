const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../db');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

const router = express.Router();

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  console.log('Token:', token);
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
   jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('Token verification error:', err.message);
      return res.status(403).json({ error: 'Failed to authenticate token' });
    }
    console.log('Decoded token:', decoded); 
    req.userId = decoded.id;
    next();
  });
};

// Utility function to generate JWT token
const generateToken = (userId, email) => {
  return jwt.sign({ id: userId, email }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Sign Up
router.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashedPassword]);
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ error: 'Error creating user' });
  }
});

// Sign In
router.post('/signin', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (user && await bcrypt.compare(password, user.password)) {
      const token = generateToken(user.id, user.email);
      res.json({ token, userId: user.id });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (err) {
    console.error('Error signing in:', err);
    res.status(500).json({ error: 'Error signing in' });
  }
});

// Forgot Password
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const token = crypto.randomBytes(20).toString('hex');
  const expiresAt = new Date(Date.now() + 3600000);

  try {
    const result = await pool.query('SELECT * FROM password_resets WHERE email = $1', [email]);
    if (result.rows.length > 0) {
      await pool.query('UPDATE password_resets SET token = $1, expires_at = $2 WHERE email = $3', [token, expiresAt, email]);
    } else {
      await pool.query('INSERT INTO password_resets (email, token, expires_at) VALUES ($1, $2, $3)', [email, token, expiresAt]);
    }

    const transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const resetLink = `http://localhost:3000/reset-password/${token}`;
    await transporter.sendMail({
      to: email,
      subject: 'Password Reset',
      text: `Click the link to reset your password: ${resetLink}`,
    });

    res.status(200).json({ message: 'Reset link sent to your email.' });
  } catch (err) {
    console.error('Error sending reset link:', err);
    res.status(500).json({ error: 'Error sending reset link.' });
  }
});

// Reset Password
router.post('/reset-password/:token', async (req, res) => {
  const { password } = req.body;
  const { token } = req.params;

  try {
    const result = await pool.query('SELECT * FROM password_resets WHERE token = $1 AND expires_at > NOW()', [token]);
    const resetRequest = result.rows[0];

    if (!resetRequest) {
      return res.status(400).json({ error: 'Invalid or expired token.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, resetRequest.email]);
    await pool.query('DELETE FROM password_resets WHERE token = $1', [token]);

    res.status(200).json({ message: 'Password has been reset successfully.' });
  } catch (err) {
    console.error('Error resetting password:', err);
    res.status(500).json({ error: 'Error resetting password.' });
  }
});

module.exports = router;
module.exports.verifyToken = verifyToken;
module.exports.generateToken = generateToken; // Export only the router

