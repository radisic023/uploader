// --- Imports ---
const express = require('express');
const fileUpload = require('express-fileupload');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const NodeClam = require('clamscan');
const sqlite3 = require('sqlite3').verbose();

// --- Constants ---
const app = express();
const PORT = 3000;
const SECRET = crypto.randomBytes(64).toString('hex'); // secret
const ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex'); // enycryption
const DB_PATH = './database.sqlite';
const uploadsDir = path.join(__dirname, 'uploads');

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('Connected to SQLite database');
        
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            last_login DATETIME,
            failed_attempts INTEGER DEFAULT 0,
            locked_until DATETIME
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            encrypted_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            type TEXT NOT NULL,
            tag TEXT,
            password TEXT,
            active INTEGER DEFAULT 1,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        db.get("SELECT * FROM users WHERE role = 'admin' LIMIT 1", (err, row) => {
            if (err) {
                console.error('Error checking admin user:', err);
            } else if (!row) {
                const adminId = crypto.randomUUID();
                const adminPass = crypto.randomBytes(16).toString('hex');
                const hashedPass = crypto.createHash('sha256').update(adminPass).digest('hex');
                
                db.run('INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)',
                    [adminId, 'admin', hashedPass, 'admin'],
                    (err) => {
                        if (err) {
                            console.error('Error creating admin user:', err);
                        } else {
                            console.log('Default admin created with password:', adminPass);
                        }
                    }
                );
            }
        });
    }
});

// --- Initialize Directories ---
ensureDirectoryExists(uploadsDir);

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload({
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max 
    abortOnLimit: true
}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// security
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});

// user contect
app.use((req, res, next) => {
    const token = req.cookies.token;
    if (token) {
        jwt.verify(token, SECRET, (err, decodedUser) => {
            if (!err) {
                res.locals.user = decodedUser;
            } else {
                res.locals.user = null;
                res.clearCookie('token');
            }
        });
    } else {
        res.locals.user = null;
    }
    next();
});

// rate limit
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: 'Too many login attempts, please try again later'
});

// --- Utility Functions ---
function ensureDirectoryExists(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function encryptId(id) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = cipher.update(id.toString(), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;
}

function decryptId(encryptedData) {
    const [ivHex, encrypted, authTagHex] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function addLog(user, action, req) {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    
    db.run('INSERT INTO logs (username, action, ip_address, user_agent) VALUES (?, ?, ?, ?)',
        [user.username, action, ip, userAgent],
        (err) => {
            if (err) {
                console.error('Error adding log:', err);
            }
        }
    );
}

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function createUser({ username, password, role }) {
    const id = crypto.randomUUID();
    const hashedPass = hashPassword(password);
    
    return new Promise((resolve, reject) => {
        db.run('INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)',
            [id, username, hashedPass, role],
            (err) => {
                if (err) {
                    console.error('Error creating user:', err);
                    reject(err);
                } else {
                    resolve(id);
                }
            }
        );
    });
}

// --- Authentication ---
function authenticateToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');
    
    jwt.verify(token, SECRET, (err, user) => {
        if (err) {
            res.clearCookie('token');
            return res.redirect('/login');
        }
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).render('error', { 
            message: 'Access denied',
            error: { status: 403, stack: '' }
        });
    }
    next();
}

// --- Routes ---

// Auth Routes
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
    if (res.locals.user) {
        return res.redirect('/upload');
    }
    res.render('login', { error: null });
});

app.post('/login', loginLimiter, async (req, res) => {
    const { username, password, remember } = req.body;
    const hashedPass = hashPassword(password);
    
    try {
        const user = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
                if (err) reject(err);
                else resolve(user);
            });
        });

        if (!user || user.password !== hashedPass) {

            if (user) {
                db.run('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?', [user.id]);
                
                if (user.failed_attempts >= 4) {
                    const lockTime = new Date(Date.now() + 15 * 60000); // 15 minutes
                    db.run('UPDATE users SET locked_until = ? WHERE id = ?', [lockTime, user.id]);
                }
            }
            
            return res.render('login', { error: 'Invalid username or password' });
        }

        if (user.locked_until && new Date(user.locked_until) > new Date()) {
            return res.render('login', { 
                error: 'Account is temporarily locked. Please try again later.' 
            });
        }

        db.run('UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

        const token = jwt.sign(user, SECRET, { 
            expiresIn: remember ? '7d' : '1h',
            algorithm: 'HS512'
        });

        res.cookie('token', token, { 
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: remember ? 7 * 24 * 60 * 60 * 1000 : 60 * 60 * 1000 
        });

        addLog(user, 'Logged in', req);
        res.redirect('/upload');

    } catch (err) {
        console.error('Login error:', err);
        res.render('login', { error: 'An error occurred during login' });
    }
});

app.get('/logout', (req, res) => {
    if (req.user) {
        addLog(req.user, 'Logged out', req);
    }
    res.clearCookie('token');
    res.redirect('/login');
});

// Dashboard
app.get('/dashboard', authenticateToken, requireAdmin, (req, res) => {
    res.render('dashboard', { user: req.user, currentPage: 'dashboard' });
});

// Upload
app.get('/upload', authenticateToken, (req, res) => {
    res.render('upload', { user: req.user, currentPage: 'upload' });
});

app.post('/upload', authenticateToken, (req, res) => {
    const file = req.files?.file;
    if (!file) return res.status(400).send('No files uploaded');

    const tag = req.body.tag || 'general';
    const password = req.body.password || null;
    const uploadDir = path.join(uploadsDir, 'tags', tag);

    ensureDirectoryExists(uploadDir);

    const fileId = crypto.randomUUID();
    const encryptedId = encryptId(fileId);
    const filePath = path.join(uploadDir, file.name);

    file.mv(filePath, (err) => {
        if (err) return res.status(500).send('File upload failed');
        
        db.run(`INSERT INTO files (id, encrypted_id, filename, type, tag, password) 
                VALUES (?, ?, ?, ?, ?, ?)`,
            [fileId, encryptedId, file.name, file.mimetype.startsWith('image/') ? 'image' : 'file', tag, password],
            (err) => {
                if (err) {
                    console.error('Error saving file to database:', err);
                    return res.status(500).send('Database error');
                }
                addLog(req.user, `Uploaded file "${file.name}" under tag "${tag}"`, req);
                res.redirect('/manage');
            }
        );
    });
});

// manage
app.get('/manage', authenticateToken, (req, res) => {
    // Filter files based on user role
    const query = req.user.role === 'admin' 
        ? 'SELECT * FROM files'
        : 'SELECT * FROM files WHERE active = 1';
        
    db.all(query, [], (err, files) => {
        if (err) {
            console.error('Error fetching files:', err);
            return res.status(500).send('Database error');
        }
        res.render('manage', { user: req.user, files, currentPage: 'manage' });
    });
});

app.post('/toggleLink', authenticateToken, requireAdmin, (req, res) => {
    db.run('UPDATE files SET active = NOT active WHERE id = ?', [req.body.id], (err) => {
        if (err) {
            console.error('Error toggling file status:', err);
        } else {
            db.get('SELECT filename FROM files WHERE id = ?', [req.body.id], (err, file) => {
                if (!err && file) {
                    addLog(req.user, `Toggled link for "${file.filename}"`, req);
                }
            });
        }
        res.redirect('/manage');
    });
});

app.post('/deleteFile', authenticateToken, requireAdmin, (req, res) => {
    db.get('SELECT * FROM files WHERE id = ?', [req.body.id], (err, file) => {
        if (err || !file) return res.redirect('/manage');

        const filePath = file.tag
            ? path.join(uploadsDir, 'tags', file.tag, file.filename)
            : path.join(uploadsDir, file.filename);

        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

        db.run('DELETE FROM files WHERE id = ?', [req.body.id], (err) => {
            if (err) {
                console.error('Error deleting file from database:', err);
            } else {
                addLog(req.user, `Deleted file "${file.filename}"`, req);
            }
            res.redirect('/manage');
        });
    });
});

// access
app.get('/file/:encryptedId', (req, res) => {
    try {
        const id = decryptId(req.params.encryptedId);
        db.get('SELECT * FROM files WHERE id = ? AND active = 1', [id], (err, file) => {
            if (err || !file) return res.status(404).send('File not found');

            const filePath = path.join(
                uploadsDir,
                file.tag ? path.join('tags', file.tag) : '',
                file.filename
            );
            if (!fs.existsSync(filePath)) return res.status(404).send('File not found');
            
            // Log file access
            addLog({ username: 'Anonymous' }, `Accessed file "${file.filename}"`, req);
            res.sendFile(filePath);
        });
    } catch {
        res.status(400).send('Invalid link');
    }
});

// log
app.get('/logs', authenticateToken, requireAdmin, (req, res) => {
    db.all('SELECT * FROM logs ORDER BY timestamp DESC', [], (err, logs) => {
        if (err) {
            console.error('Error fetching logs:', err);
            return res.status(500).send('Database error');
        }

        function formatLogTimestamp(timestamp) {
            const date = new Date(timestamp);
            const options = { day: '2-digit', month: '2-digit', year: 'numeric' };
            const timeOptions = { hour: '2-digit', minute: '2-digit' };
            const formattedDate = date.toLocaleDateString('de-DE', options);
            const formattedTime = date.toLocaleTimeString('de-DE', timeOptions);
            return `Datum: ${formattedDate}, Uhrzeit: ${formattedTime}`;
        }

        res.render('logs', { logs, currentPage: '/logs', formatLogTimestamp });
    });
});

// Users
app.get('/users', authenticateToken, requireAdmin, (req, res) => {
    db.all('SELECT * FROM users', [], (err, users) => {
        if (err) {
            console.error('Error fetching users:', err);
            return res.status(500).send('Database error');
        }
        res.render('users', { users, currentPage: 'users', error: null });
    });
});

app.post('/createUser', authenticateToken, requireAdmin, async (req, res) => {
    const { username, password, role } = req.body;

    try {
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
                if (err) reject(err);
                else resolve(user);
            });
        });

        if (existingUser) {
            return res.redirect('/users?error=exists');
        }

        await createUser({ username, password, role });
        addLog(req.user, `Created user "${username}"`, req);
        res.redirect('/users');
    } catch (err) {
        console.error('Error creating user:', err);
        res.redirect('/users?error=database');
    }
});

app.post('/deleteUser', authenticateToken, requireAdmin, (req, res) => {
    const { id } = req.body;
    
    // del yourself prev
    if (id === req.user.id) {
        return res.status(400).send('Cannot delete your own account');
    }

    db.get('SELECT username FROM users WHERE id = ?', [id], (err, user) => {
        if (err || !user) return res.redirect('/users');

        db.run('DELETE FROM users WHERE id = ?', [id], (err) => {
            if (!err) {
                addLog(req.user, `Deleted user "${user.username}"`, req);
            }
            res.redirect('/users');
        });
    });
});

app.post('/editUser', authenticateToken, requireAdmin, (req, res) => {
    const { id, username, password, role } = req.body;

    // own role 
    if (id === req.user.id && role !== req.user.role) {
        return res.status(400).send('Cannot change your own role');
    }

    if (password && password.trim() !== '') {
        const hashedPass = hashPassword(password);
        db.run('UPDATE users SET username = ?, password = ?, role = ? WHERE id = ?',
            [username, hashedPass, role, id],
            (err) => {
                if (!err) {
                    addLog(req.user, `Edited user "${username}" and changed password`, req);
                }
                if (req.user.id === id) {
                    res.clearCookie('token');
                    return res.redirect('/login');
                }
                res.redirect('/users');
            }
        );
    } else {
        db.run('UPDATE users SET username = ?, role = ? WHERE id = ?',
            [username, role, id],
            (err) => {
                if (!err) {
                    addLog(req.user, `Edited user "${username}"`, req);
                }
                res.redirect('/users');
            }
        );
    }
});

// Route für Echtzeitstatistiken
app.get('/api/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const stats = await new Promise((resolve, reject) => {
            db.get(`
                SELECT 
                    (SELECT COUNT(*) FROM users) as totalUsers,
                    (SELECT COUNT(*) FROM files) as totalFiles,
                    (SELECT COUNT(*) FROM files WHERE active = 1) as activeLinks
            `, [], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        res.json(stats);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Statistiken' });
    }
});

// --- Start Server ---
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
