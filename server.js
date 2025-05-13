require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');
const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
const client = new MongoClient(process.env.MONGODB_URI);
let db, users;
client.connect().then(() => {
    db = client.db();
    users = db.collection("users");
    console.log("✅ Connected to MongoDB");
});

// Middleware
app.set('view engine', 'ejs');
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        collectionName: "sessions"
    }),
    cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

// Pass user info to all templates
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

// Middleware for authenticated users
function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.redirect('/login');
}

// Middleware for admin users
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.user_type === 'admin') return next();
    res.status(403).send("403 Forbidden - Admins only");
}

// Routes
app.get('/', (req, res) => {
    res.render("index");
});

app.get('/signup', (req, res) => {
    res.render("signup");
});

app.post('/signup', async (req, res) => {
    try {
        const schema = Joi.object({
            name: Joi.string().required(),
            email: Joi.string().email().required(),
            password: Joi.string().min(6).required()
        });

        const { error } = schema.validate(req.body);
        if (error) return res.send("Invalid input. <a href='/signup'>Try again</a>");

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        await users.insertOne({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
            user_type: 'user'
        });

        req.session.user = { name: req.body.name, user_type: 'user' };
        res.redirect('/members');
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error. Please try again later.");
    }
});

app.get('/login', (req, res) => {
    res.render("login");
});

app.post('/login', async (req, res) => {
    try {
        const schema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().required()
        });

        const { error } = schema.validate(req.body);
        if (error) return res.send("Invalid input. <a href='/login'>Try again</a>");

        const user = await users.findOne({ email: req.body.email });
        if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
            return res.send("Invalid credentials. <a href='/login'>Try again</a>");
        }

        req.session.user = { name: user.name, user_type: user.user_type || 'user' };
        res.redirect('/members');
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error. Please try again later.");
    }
});

app.get('/members', isAuthenticated, (req, res) => {
    res.render("members");
});

app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const userList = await users.find().toArray();
        res.render("admin", { users: userList });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error loading admin panel");
    }
});

app.post('/promote', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const email = req.body.email;
        await users.updateOne({ email: email }, { $set: { user_type: 'admin' } });
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send("Error promoting user");
    }
});

app.post('/demote', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const email = req.body.email;
        await users.updateOne({ email: email }, { $set: { user_type: 'user' } });
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send("Error demoting user");
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.send("Error logging out");
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

// 404 Handler
app.use((req, res) => {
    res.status(404).render("404");
});

// Start the server
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
