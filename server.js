// server.js - Backend API Server
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// Middleware
app.use(cors());
app.use(express.json());

// Create directories if they don't exist
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

// Simple file-based database (use a real DB in production)
const DB_FILE = path.join(DATA_DIR, 'db.json');
let db = { users: [], songs: [], playlists: [] };

// Load database
if (fs.existsSync(DB_FILE)) {
  db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

// Save database
function saveDb() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['audio/mpeg', 'audio/mp3'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only MP3 files are allowed'));
    }
  }
});

// Auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// Routes

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user exists
    if (db.users.find(u => u.email === email)) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Check user limit (max 5 users for free tier)
    if (db.users.length >= 5) {
      return res.status(400).json({ error: 'Maximum user limit reached (5 users)' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = {
      id: Date.now().toString(),
      username,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    db.users.push(user);
    saveDb();

    // Generate token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: { id: user.id, username: user.username, email: user.email }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = db.users.find(u => u.email === email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: { id: user.id, username: user.username, email: user.email }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Upload song
app.post('/api/songs/upload', authenticateToken, upload.single('song'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Extract metadata from filename (you could use a library like music-metadata)
    const filename = req.file.originalname;
    const title = filename.replace(/\.[^/.]+$/, ''); // Remove extension

    const song = {
      id: Date.now().toString(),
      title,
      artist: 'Unknown Artist',
      filename: req.file.filename,
      originalName: req.file.originalname,
      uploadedBy: req.user.id,
      uploadedAt: new Date().toISOString()
    };

    db.songs.push(song);
    saveDb();

    res.json({ message: 'Song uploaded successfully', song });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Get all songs
app.get('/api/songs', authenticateToken, (req, res) => {
  const songs = db.songs.map(({ id, title, artist, uploadedAt }) => ({
    id,
    title,
    artist,
    uploadedAt
  }));
  res.json(songs);
});

// Stream song
app.get('/api/songs/:id/stream', (req, res) => {
  try {
    // Check token from query param (for audio player compatibility)
    const token = req.query.token;
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err) => {
      if (err) {
        return res.status(403).json({ error: 'Invalid token' });
      }

      const song = db.songs.find(s => s.id === req.params.id);
      if (!song) {
        return res.status(404).json({ error: 'Song not found' });
      }

      const filePath = path.join(UPLOAD_DIR, song.filename);
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
      }

      const stat = fs.statSync(filePath);
      const range = req.headers.range;

      if (range) {
        // Handle range requests for seeking
        const parts = range.replace(/bytes=/, '').split('-');
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : stat.size - 1;
        const chunksize = (end - start) + 1;
        const stream = fs.createReadStream(filePath, { start, end });

        res.writeHead(206, {
          'Content-Range': `bytes ${start}-${end}/${stat.size}`,
          'Accept-Ranges': 'bytes',
          'Content-Length': chunksize,
          'Content-Type': 'audio/mpeg'
        });

        stream.pipe(res);
      } else {
        // Stream entire file
        res.writeHead(200, {
          'Content-Length': stat.size,
          'Content-Type': 'audio/mpeg'
        });

        fs.createReadStream(filePath).pipe(res);
      }
    });
  } catch (error) {
    console.error('Stream error:', error);
    res.status(500).json({ error: 'Streaming failed' });
  }
});

// Delete song (optional)
app.delete('/api/songs/:id', authenticateToken, (req, res) => {
  try {
    const songIndex = db.songs.findIndex(s => s.id === req.params.id);
    if (songIndex === -1) {
      return res.status(404).json({ error: 'Song not found' });
    }

    const song = db.songs[songIndex];

    // Check if user uploaded this song or is admin
    if (song.uploadedBy !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Delete file
    const filePath = path.join(UPLOAD_DIR, song.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Remove from database
    db.songs.splice(songIndex, 1);
    saveDb();

    res.json({ message: 'Song deleted successfully' });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', users: db.users.length, songs: db.songs.length });
});

// Playlist Routes

// Get all playlists for user
app.get('/api/playlists', authenticateToken, (req, res) => {
  try {
    const userPlaylists = db.playlists
      .filter(p => p.userId === req.user.id)
      .map(({ id, name, description, songIds, createdAt }) => ({
        id,
        name,
        description,
        songCount: songIds.length,
        createdAt
      }));
    res.json(userPlaylists);
  } catch (error) {
    console.error('Get playlists error:', error);
    res.status(500).json({ error: 'Failed to load playlists' });
  }
});

// Create playlist
app.post('/api/playlists', authenticateToken, (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Playlist name is required' });
    }

    const playlist = {
      id: Date.now().toString(),
      name,
      description: description || '',
      userId: req.user.id,
      songIds: [],
      createdAt: new Date().toISOString()
    };

    db.playlists.push(playlist);
    saveDb();

    res.json({ message: 'Playlist created', playlist });
  } catch (error) {
    console.error('Create playlist error:', error);
    res.status(500).json({ error: 'Failed to create playlist' });
  }
});

// Delete playlist
app.delete('/api/playlists/:id', authenticateToken, (req, res) => {
  try {
    const playlistIndex = db.playlists.findIndex(
      p => p.id === req.params.id && p.userId === req.user.id
    );

    if (playlistIndex === -1) {
      return res.status(404).json({ error: 'Playlist not found' });
    }

    db.playlists.splice(playlistIndex, 1);
    saveDb();

    res.json({ message: 'Playlist deleted' });
  } catch (error) {
    console.error('Delete playlist error:', error);
    res.status(500).json({ error: 'Failed to delete playlist' });
  }
});

// Get songs in playlist
app.get('/api/playlists/:id/songs', authenticateToken, (req, res) => {
  try {
    const playlist = db.playlists.find(
      p => p.id === req.params.id && p.userId === req.user.id
    );

    if (!playlist) {
      return res.status(404).json({ error: 'Playlist not found' });
    }

    const playlistSongs = playlist.songIds
      .map(songId => db.songs.find(s => s.id === songId))
      .filter(Boolean)
      .map(({ id, title, artist }) => ({ id, title, artist }));

    res.json(playlistSongs);
  } catch (error) {
    console.error('Get playlist songs error:', error);
    res.status(500).json({ error: 'Failed to load playlist songs' });
  }
});

// Add/Update songs in playlist
app.post('/api/playlists/:id/songs', authenticateToken, (req, res) => {
  try {
    const { songIds } = req.body;

    if (!Array.isArray(songIds)) {
      return res.status(400).json({ error: 'songIds must be an array' });
    }

    const playlist = db.playlists.find(
      p => p.id === req.params.id && p.userId === req.user.id
    );

    if (!playlist) {
      return res.status(404).json({ error: 'Playlist not found' });
    }

    // Replace entire song list with new one
    playlist.songIds = songIds;
    saveDb();

    res.json({ message: 'Playlist updated', songCount: songIds.length });
  } catch (error) {
    console.error('Update playlist songs error:', error);
    res.status(500).json({ error: 'Failed to update playlist' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🎵 Music streaming server running on port ${PORT}`);
  console.log(`📊 Users: ${db.users.length}/5 | Songs: ${db.songs.length}`);
});
