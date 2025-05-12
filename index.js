require("./utils.js");
require('dotenv').config();
const express = require('express');

const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();
const port = process.env.PORT || 8000;
const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('user');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.set('view engine', 'ejs');

app.use(session({ 
    secret: node_session_secret,
    store: mongoStore, 
    saveUninitialized: false, 
    resave: true
}));

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/signup', (req, res) => {
    res.render('signup');
});
app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().max(30).required(),
        password: Joi.string().max(20).required()
    });
    const validationResult = schema.validate({name, email, password});

    if (validationResult.error != null) {
        if(name == "") {
            res.render('signup', {error: 'Name is required.'});
            return;
        }
        if(email == "") {
            res.render('signup', {error: 'Email is required.'});
            return;
        }
        if(password == "") {
            res.render('signup', {error: 'Password is required.'});
            return;
        }
    }
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({name: name, email: email, password: hashedPassword});

    res.redirect("/cats");
});
app.get('/login', (req, res) => {
    res.render('login');
});
app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
		{
			email: Joi.string().email().max(30).required(),
            password: Joi.string().max(20).required()
		});
    const validationResult = schema.validate({email, password});
    if (validationResult.error != null) {
        res.send(`
            Invalid email/password combination.<br><br>
            <a href="/login">Try again</a>
            `);
        return;
    }

    const result = await userCollection.find({email: email}).project({email: 1, name: 1, password: 1, _id: 1}).toArray();
    if (result.length == 1 && await bcrypt.compare(password, result[0].password)) {
        const name = result[0].name;
		req.session.authenticated = true;
		req.session.name = name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/cats');
		return;
	} else {
		res.send(`
            User and password not found.<br><br>
            <a href="/login">Try again</a>
            `);
		return;
	}
});
app.get('/cats', (req, res) => {
    if(!req.session.authenticated) {
        res.redirect('/');
    }
    var images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
    res.render('cats', {name: req.session.name, images: images});

});

app.get('/admin', async (req, res) => {
    if(!req.session.authenticated) {
        res.redirect('/');
    }
    const result = await userCollection.find({name: req.session.name}).project({email: 1, name: 1, password: 1, user_type: 1, _id: 1}).toArray();
    if (result[0].user_type != "admin") {
        res.status(403).send("You are not authorized to access this page.");
        return;
    }
    const users = await userCollection.find({}).project({email: 1, name: 1, user_type: 1, _id: 1}).toArray();
    res.render('admin', {users: users});
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log('Session destroy error:', err);
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

app.use(express.static(__dirname + "/public"));

app.get(/.*/, (req,res) => {
	res.status(404);
    res.render('404');
})

app.listen(port, () => {
	console.log("Node application listening on port "+ port);
}); 