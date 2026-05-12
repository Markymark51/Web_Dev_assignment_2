require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const Joi = require("joi");
const { MongoClient } = require("mongodb");

const app = express();
const PORT = process.env.PORT || 3000;
const expireTimeMS = 60 * 60 * 1000;

const MONGODB_DATABASE = process.env.MONGODB_DATABASE;

app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(express.static(__dirname + "/public"));

const client = new MongoClient(
  process.env.MONGODB_CONNECT_NON_SRV, {}
);

const db = client.db(process.env.MONGODB_DATABASE);
const userCollection = db.collection("users");

const mongostore = MongoStore.create({
    mongoUrl: process.env.MONGODB_CONNECT_NON_SRV,
	dbName: process.env.MONGODB_DATABASE,
    collectionName: 'sessions',
	ttl: expireTimeMS / 1000,
  	crypto: {
    secret: process.env.MONGODB_SESSION_SECRET
  }
}); 

app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: expireTimeMS }, 
  store: mongostore
}));

app.use((req, res, next) => {
  const route = req.path;
  if (route === '/') res.locals.activePage = 'home';
  else if (route === '/login') res.locals.activePage = 'login';
  else if (route === '/signup') res.locals.activePage = 'signup';
  else if (route === '/members') res.locals.activePage = 'members';
  else if (route === '/admin' || route === '/adminError') res.locals.activePage = 'admin';
  else res.locals.activePage = '';
  next();
});

function loginCheck(req, res, next) {
    if (req.session.authenticated) {
        return next();
    }
    return res.redirect('/login');
}

async function adminCheck(req, res, next) {
    if (req.session.userType === 'admin') {
        return next();
    }
	else
	{
		currentUser = await userCollection.findOne({ username: req.session.username }, { projection: { user_type: 1 } });
		if (!currentUser || currentUser.user_type !== 'admin') {
			return res.redirect('/adminError');
		}
		return next();
	}

    return res.redirect('/adminError');
}

app.get('/', (req, res) => {

	if(req.session.authenticated) 
	{
		res.render('index', {
			firstAction: "members",
			secondAction: "logout",
			buttonLabel1: "Go to Members",
			buttonLabel2: "Log Out", greetUser: true,
			username: req.session.username,
			login: false,
			activePage: 'home'});
	}
	else 
	{
		res.render('index', {
			firstAction: "signup",
		 	secondAction: "login", 
			buttonLabel1: "Sign Up", 
			buttonLabel2: "Log In", 
			greetUser: false, 
			username: null, 
			login: true,
			activePage: 'home'});
	}

});

app.get('/signup', (req, res) => {
	res.render('login', {
		signup: true, 
		Action: "/signupSubmit", 
		Title: "Sign Up", 
		ButtonLabel: "Sign Up",
		error: "",
		activePage: 'signup'
	});
});


app.get('/login', (req, res) => {
	res.render('login', {
		signup: false, 
		Action: "/loginSubmit", 
		Title: "Log In", 
		ButtonLabel: "Log In",
		error: "",
		activePage: 'login'
	});
});

app.get('/admin', loginCheck, adminCheck, async (req, res) => {

	const users = await userCollection.find({}).project({username: 1, email: 1, user_type: 1}).toArray();
	res.render('admin', { users: users, activePage: 'admin'});
});

app.post('/promoteUser', loginCheck, adminCheck, async (req, res) => {
	const username = req.body.username;
	const user = await userCollection.findOne({ username: username });
	if (user) {
		await userCollection.updateOne({ username: username }, { $set: { user_type: 'admin' } });
	}
	res.redirect('/admin');
});

app.post('/demoteUser', loginCheck, adminCheck, async (req, res) => {
	const username = req.body.username;
	const user = await userCollection.findOne({ username: username });
	if (user) {
		await userCollection.updateOne({ username: username }, { $set: { user_type: 'user' } });
	}

	if(username === req.session.username) {
		req.session.userType = 'user';
	}
	res.redirect('/admin');
});

app.get('/adminError', (req, res) => {
	res.status(403);
	res.render('adminError', { activePage: 'admin' });
});

app.post('/signupSubmit', async (req, res) => {
	const username = req.body.username;
	const email = req.body.email;
	const password = req.body.password;

	let validInput = true;
	let emptyMessage = "";
	if (!username) {
		emptyMessage += "Username is required. \n";
		validInput = false;
	}
	if (!email) {
		emptyMessage += "Email is required. \n";
		validInput = false;
	} 
	if (!password) {
		emptyMessage += "Password is required. \n";
		validInput = false;
	}

	if (!validInput) {
		res.render('login', {
		signup: true, 
		Action: "/signupSubmit", 
		Title: "Sign Up", 
		ButtonLabel: "Sign Up",
		error: emptyMessage,
		activePage: 'signup'
	});
		return;
	}

	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
			email: Joi.string().email().required(),
			password: Joi.string().max(30).required()
	});

	const validationResult = schema.validate({ username, email, password });

	if (validationResult.error != null) {
		console.log(validationResult.error);

		res.redirect("/signup");
		
		return;
	}

	var hashedPassword = await bcrypt.hash(password, 10);

	await userCollection.insertOne({username: username, email: email, password: hashedPassword, user_type: 'user'});

	req.session.authenticated = true;
    req.session.username = username;
    req.session.email = email;

	res.redirect("/members");
});

app.post('/loginSubmit', async (req, res) => {
	const email = req.body.email;
	const password = req.body.password;

	 const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(30).required()
    });

	const validationResult = schema.validate({ email, password });
    if (validationResult.error) {
		res.render('login', {
			signup: false, 
			Action: "/loginSubmit",
			Title: "Log In",
			ButtonLabel: "Log In",
			error: "Invalid email/password combination.",
			activePage: 'login'
		});
		return;
    }
 
	const result = await userCollection.find({email: email}).project({email: 1, password: 1, username: 1, user_type: 1}).toArray();

	if (result.length != 1) {
		res.render('login', {
			signup: false, 
			Action: "/loginSubmit",
			Title: "Log In",
			ButtonLabel: "Log In",
			error: "Invalid email/password combination.",
			activePage: 'login'
		});
		return;
	}
	const user = result[0];

	const isMatch = await bcrypt.compare(password, user.password);

	if (!isMatch) {
		res.render('login', {
			signup: false, 
			Action: "/loginSubmit",
			Title: "Log In",
			ButtonLabel: "Log In",
			error: "Invalid password",
			activePage: 'login'
		});
		return;
	} 

	req.session.authenticated = true;
    req.session.username = user.username;
    req.session.email = user.email;
    req.session.userType = user.user_type;
	res.redirect("/members");
});

app.get("/members", loginCheck, (req, res) => {
	res.render("members", {username: req.session.username, email: req.session.email, activePage: 'members'});
});

app.get("/logout", (req, res) => {
	req.session.destroy();

	res.redirect("/");
});

app.use((req,res) => {
	res.status(404);
	res.render('404');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});