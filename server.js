require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

const client = new MongoClient(process.env.MONGODB_URI);
let db, users;
client.connect().then(() => {
    db = client.db();
    users = db.collection("users");
});

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

function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.redirect('/');
}

app.get('/', (req, res) => {
    if (!req.session.user) {
        return res.send(`
      <h1>Welcome</h1>
      <a href="/signup">Sign Up</a> |
      <a href="/login">Log In</a>
    `);
    }
    res.send(`
    <h1>Hello, ${req.session.user.name}</h1>
    <a href="/members">Members Area</a> |
    <a href="/logout">Log Out</a>
  `);
});

app.get('/signup', (req, res) => res.sendFile(__dirname + '/views/signup.html'));

app.post('/signup', async (req, res) => {
    const schema = Joi.object({
        name: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });
    const { error } = schema.validate(req.body);
    if (error) return res.send("Invalid input. <a href='/signup'>Try again</a>");

    const hashed = await bcrypt.hash(req.body.password, 10);
    await users.insertOne({ name: req.body.name, email: req.body.email, password: hashed });
    req.session.user = { name: req.body.name };
    res.redirect('/members');
});

app.get('/login', (req, res) => res.sendFile(__dirname + '/views/login.html'));

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
    req.session.user = { name: user.name };
    res.redirect('/members');
});

app.get('/members', isAuthenticated, (req, res) => {
    const imgNum = Math.floor(Math.random() * 3) + 1;
    res.send(`
    <h1>Welcome to the Members Area, ${req.session.user.name}</h1>
    <img src="/images/${imgNum}.gif" width="300"/><br>
    <a href="/logout">Log Out</a>
  `);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.use((req, res) => {
    res.status(404).sendFile(__dirname + '/views/404.html');
});

app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
