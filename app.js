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

app.use(express.urlencoded({extended: false}));
app.use(express.static(__dirname + "/public"));

app.get('/', (req, res) => {
	if(req.session.authenticated) {
		res.send(`
			<h1>Welcome, ${req.session.username}!</h1>
			<form action="/members" method="GET">
				<button type="submit">go to members</button>
			</form>
			<form action="/logout" method="GET">
				<button type="submit">Log Out</button>
			</form>
		`);
	}
	else {
	res.send(`
            <h1>Home</h1>
            <form action="/signup" method="GET">
                <button type="submit">Sign Up</button>
            </form>
            <form action="/login" method="GET">
                <button type="submit">Log In</button>
            </form>
        `);
	}

});

app.get('/signup', (req, res) => {
	res.send(`
			<h1>Sign Up</h1>
			<form action="/signupSubmit" method="POST">
				<label for="username">Username:</label>
				<input type="text" id="username" name="username"><br><br>
				<label for="email">Email:</label>
				<input type="email" id="email" name="email"><br><br>
				<label for="password">Password:</label>
				<input type="password" id="password" name="password"><br><br>
				<button type="submit">Sign Up</button>
			</form>
		`);
});

app.get('/login', (req, res) => {
	res.send(`
			<h1>Log In</h1> 
			<form action="/loginSubmit" method="POST">
				<label for="email">Email:</label>
				<input type="email" id="email" name="email" required><br><br>
				<label for="password">Password:</label>
				<input type="password" id="password" name="password" required><br><br>
				<button type="submit">Log In</button>
			</form>
		`);
});

app.post('/signupSubmit', async (req, res) => {
	const username = req.body.username;
	const email = req.body.email;
	const password = req.body.password;

	let validInput = true;
	let emptyMessage = "/signupError?";
	if (!username) {
		emptyMessage += "<p>Username is required.</p>";
		validInput = false;
	}
	if (!email) {
		emptyMessage += "<p>Email is required.</p>";
		validInput = false;
	} 
	if (!password) {
		emptyMessage += "<p>Password is required.</p>";
		validInput = false;
	}

	if (!validInput) {
		res.send(`
			<h1>Sign Up Error</h1>
			<p>${emptyMessage}</p>
			<a href="/signup">Go back to Sign Up</a>
		`);
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

	await userCollection.insertOne({username: username, email: email, password: hashedPassword});

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
        res.send(`
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
        `);
		return;
    }
 
	const result = await userCollection.find({email: email}).project({email: 1, password: 1, username: 1}).toArray();

	if (result.length != 1) {
		return res.send(`
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
        `);
		return;
	}
	const user = result[0];

	const isMatch = await bcrypt.compare(password, user.password);

	if (!isMatch) {
		res.send(`
            <p>Invalid password.</p>
            <a href="/login">Try again</a>
        `);
		return;
	} 

	req.session.authenticated = true;
    req.session.username = user.username;
    req.session.email = user.email;

	res.redirect("/members");
});

app.get("/members", (req, res) => {
	if (req.session.authenticated) {
		const images = ["/images/dbd.png", "/images/scrapMechanic.png", "/images/silksong.png"];
		const randomImage = images[Math.floor(Math.random() * images.length)];

		res.send(`
			<h1>Welcome, ${req.session.username}!</h1>
			<p>Email: ${req.session.email}</p>
			<p>Heres a random game that I like :)</p>
			<form action="/logout" method="get">
				<button type="submit">Log Out</button>
			</form>
			<img src="${randomImage}" alt="Random Image" style="width:600px;"><br><br>
		`);
	}
	else {
		res.redirect("/");
	}
});

app.get("/logout", (req, res) => {
	req.session.destroy();

	res.redirect("/");
});

app.use((req,res) => {
	res.status(404);
	res.send("Page not found - 404");
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});