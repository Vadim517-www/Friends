const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 3000;

// Підключення до бази даних SQLite
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Error connecting to SQLite:', err.message);
    } else {
        console.log('Connected to SQLite database.');
    }
});

// Створення таблиць, якщо вони не існують
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            age INTEGER NOT NULL
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (friend_id) REFERENCES users (id) ON DELETE CASCADE
        )
    `);
});

app.use(bodyParser.json());

// Головна сторінка
app.get('/', (req, res) => {
    res.send('Welcome to the REST API server for User entity!');
});

// Отримати всіх користувачів
app.get('/users', (req, res) => {
    db.all('SELECT * FROM users', (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Error retrieving users', error: err.message });
        }
        res.json(rows);
    });
});

// Додати нового користувача
app.post('/users', (req, res) => {
    const { name, age } = req.body;
    if (!name || !age) {
        return res.status(400).json({ message: 'Name and age are required' });
    }

    const sql = 'INSERT INTO users (name, age) VALUES (?, ?)';
    db.run(sql, [name, age], function (err) {
        if (err) {
            return res.status(500).json({ message: 'Error adding user', error: err.message });
        }
        res.status(201).json({ id: this.lastID, name, age });
    });
});

// Отримати користувача за ID
app.get('/users/:id', (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const sql = 'SELECT * FROM users WHERE id = ?';

    db.get(sql, [userId], (err, row) => {
        if (err) {
            return res.status(500).json({ message: 'Error retrieving user', error: err.message });
        }
        if (!row) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(row);
    });
});

// Оновити користувача за ID
app.put('/users/:id', (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const { name, age } = req.body;

    if (!name || !age) {
        return res.status(400).json({ message: 'Name and age are required' });
    }

    const sql = 'UPDATE users SET name = ?, age = ? WHERE id = ?';
    db.run(sql, [name, age, userId], function (err) {
        if (err) {
            return res.status(500).json({ message: 'Error updating user', error: err.message });
        }
        if (this.changes === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ id: userId, name, age });
    });
});

// Видалити користувача за ID
app.delete('/users/:id', (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const sql = 'DELETE FROM users WHERE id = ?';

    db.run(sql, [userId], function (err) {
        if (err) {
            return res.status(500).json({ message: 'Error deleting user', error: err.message });
        }
        if (this.changes === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(204).send();
    });
});

// Додати друга
app.post('/users/:id/friends', (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const { friendId } = req.body;

    if (!friendId) {
        return res.status(400).json({ message: 'Friend ID is required' });
    }
    if (userId === friendId) {
        return res.status(400).json({ message: 'User cannot be friends with themselves' });
    }

    const sql = 'INSERT INTO friendships (user_id, friend_id) VALUES (?, ?)';
    db.run(sql, [userId, friendId], function (err) {
        if (err) {
            return res.status(500).json({ message: 'Error adding friend', error: err.message });
        }
        res.status(201).json({ message: 'Friend added successfully', friendshipId: this.lastID });
    });
});

// Отримати список друзів користувача
app.get('/users/:id/friends', (req, res) => {
    const userId = parseInt(req.params.id, 10);

    const sql = `
        SELECT users.id, users.name, users.age 
        FROM users 
        JOIN friendships ON users.id = friendships.friend_id 
        WHERE friendships.user_id = ?
    `;

    db.all(sql, [userId], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Error retrieving friends', error: err.message });
        }
        res.json(rows);
    });
});

// Оновити список друзів користувача
app.put('/users/:id/friends', (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const { friends } = req.body;

    if (!Array.isArray(friends)) {
        return res.status(400).json({ message: 'Friends should be an array of user IDs' });
    }

    db.serialize(() => {
        db.run('DELETE FROM friendships WHERE user_id = ?', [userId], (err) => {
            if (err) {
                return res.status(500).json({ message: 'Error clearing old friends', error: err.message });
            }

            const insertStmt = db.prepare('INSERT INTO friendships (user_id, friend_id) VALUES (?, ?)');

            friends.forEach((friendId) => {
                insertStmt.run(userId, friendId);
            });

            insertStmt.finalize();
            res.json({ message: 'Friends list updated successfully' });
        });
    });
});

// Видалити друга
app.delete('/users/:id/friends/:friendId', (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const friendId = parseInt(req.params.friendId, 10);

    const sql = 'DELETE FROM friendships WHERE user_id = ? AND friend_id = ?';

    db.run(sql, [userId, friendId], function (err) {
        if (err) {
            return res.status(500).json({ message: 'Error deleting friend', error: err.message });
        }
        if (this.changes === 0) {
            return res.status(404).json({ message: 'Friend not found' });
        }
        res.status(200).json({ message: 'Friend removed successfully' });
    });
});

// Запуск сервера
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

// Закриття підключення до бази даних при завершенні процесу
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error('Error closing SQLite connection:', err.message);
        } else {
            console.log('SQLite connection closed.');
        }
        process.exit(0);
    });
});
