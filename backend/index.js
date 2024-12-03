const express = require('express');
const cors = require('cors');
const authRoutes = require('./routes/auth');
const translateRoutes = require('./routes/translate');
const pool = require('./db'); // Import the pool
require('dotenv').config();
console.log('JWT Secret:', process.env.JWT_SECRET);

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Use routes
app.use('/api', authRoutes);
app.use('/api', translateRoutes);

// Test the database connection
pool.connect()
    .then(() => console.log('Connected to the database'))
    .catch(err => console.error('Database connection error', err.stack));

// Start the server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
