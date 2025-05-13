require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');
const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
const client = new MongoClient(process.env.MONGODB_URI);
let db, users;
client.connect().then(() => {
    db = client.db();
    users = db.collection("users");
});

// Session setup
app.use(session({
    secret: process.env.SESSION_SECRET,
    saveUninitialized: false,
    resave: true,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        collectionName: "sessions"
    }),
    cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

// Middleware to pass user to all templates
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

// Routes
app.get('/', (req, res) => {
    res.render("index");
});

app.get('/signup', (req, res) => {
    res.render("signup");
});

app.post('/signup', async (req, res) => {
    const schema = Joi.object({
        name: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const { error } = schema.validate(req.body);
    if (error) return res.send("Invalid input. <a href='/signup'>Try again</a>");

    const hashed = await bcrypt.hash(req.body.password, 10);
    await users.insertOne({ name: req.body.name, email: req.body.email, password: hashed, user_type: 'user' });
    req.session.user = { name: req.body.name, user_type: 'user' };
    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.render("login");
});

app.post('/login', async (req, res) => {
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
});

app.get('/members', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.render("members");
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

app.get('/admin', async (req, res) => {
    if (!req.session.user || req.session.user.user_type !== 'admin') return res.status(403).send("403 Forbidden - Admins only");
    const userList = await users.find().toArray();
    res.render("admin", { users: userList });
});

app.use((req, res) => {
    res.status(404).render("404");
});

app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
