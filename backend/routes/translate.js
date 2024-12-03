const express = require('express');
const axios = require('axios');
const db = require('../db');
const router = express.Router();
const jwt = require('jsonwebtoken'); // Ensure you have this package installed
require('dotenv').config();

// Middleware to authenticate the token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Get the token from the Authorization header

  if (!token) return res.sendStatus(401); // No token found

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Token is invalid
    req.user = user; // Save the user information to the request
    next(); // Proceed to the next middleware or route handler
  });
};

// Function to chunk text for large translations
const chunkText = (text, chunkSize) => {
  const chunks = [];
  for (let i = 0; i < text.length; i += chunkSize) {
    chunks.push(text.substring(i, i + chunkSize));
  }
  return chunks;
};

// Route to handle translation without saving it to the database
router.post('/translate-only', async (req, res) => {
  const { text, from, to } = req.body;

  try {
    const maxChunkSize = 1000; // Max characters per chunk
    const textChunks = chunkText(text, maxChunkSize);

    // Translate each chunk and collect results
    const translatedChunks = await Promise.all(
      textChunks.map(async (chunk) => {
        try {
          const response = await axios.get('https://translate.googleapis.com/translate_a/single', {
            params: {
              client: 'gtx',
              sl: from,
              tl: to,
              dt: 't',
              q: chunk,
            },
          });
          return response.data[0][0][0]; // Extract translated text
        } catch (apiError) {
          console.error('Error calling translation API:', apiError.message);
          throw new Error('Translation API failed');
        }
      })
    );

    // Combine the translated chunks
    const fullTranslation = translatedChunks.join(' ');

    // Return the translated text without saving it
    res.json({ translatedText: fullTranslation });
  } catch (error) {
    console.error('Error translating text:', error.message);
    res.status(500).json({ error: 'Translation failed' });
  }
});

// Route to handle translation and save it to the database
router.post('/translate', authenticateToken, async (req, res) => {
  const { text, from, to } = req.body;
  const userId = req.user.id;

  if (!userId) {
    return res.status(400).json({ error: 'User ID is missing' });
  }

  try {
    const maxChunkSize = 1000; // Max characters per chunk
    const textChunks = chunkText(text, maxChunkSize);

    // Translate each chunk and collect results
    const translatedChunks = await Promise.all(
      textChunks.map(async (chunk) => {
        try {
          const response = await axios.get('https://translate.googleapis.com/translate_a/single', {
            params: {
              client: 'gtx',
              sl: from,
              tl: to,
              dt: 't',
              q: chunk,
            },
          });
          return response.data[0][0][0]; // Extract translated text
        } catch (apiError) {
          console.error('Error calling translation API:', apiError.message);
          throw new Error('Translation API failed');
        }
      })
    );

    // Combine the translated chunks
    const fullTranslation = translatedChunks.join(' ');

    // Save translation to the database
    const query = `
      INSERT INTO translations (user_id, from_text, to_text, from_language, to_language, created_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
    `;
    await db.query(query, [userId, text, fullTranslation, from, to]);

    res.json({ translatedText: fullTranslation });
  } catch (error) {
    console.error('Error translating text:', error.message);
    res.status(500).json({ error: 'Translation failed' });
  }
});

// Fetch translation history
router.get('/user', authenticateToken, async (req, res) => {
  const userId = req.user.id; // Correctly reference user ID

  if (!userId) {
    return res.status(400).json({ error: 'User ID is missing' });
  }

  try {
    const result = await db.query(
      `SELECT id, from_text, to_text, from_language, to_language, created_at 
       FROM translations 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [userId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching translation history:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

module.exports = router;
