const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mysql = require('mysql');
const app = express();
const path = require('path');

// Set the view engine to EJS
app.set('view engine', 'ejs');

// Set the views directory
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('images'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  session({
    secret: 'your-secret-key',
    resave: true,
    saveUninitialized: true,
  })
);




//google-auth
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

passport.use(new GoogleStrategy({
  clientID: "584022367173-vvldi8jv1custkg784tg44mqdp2fuuog.apps.googleusercontent.com",
  clientSecret: "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",
  callbackURL: '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
  // Handle the user profile data
  // You can save the user to your database or perform any other actions
  done(null, profile);
}));




const pool = mysql.createPool({
  host: 'db4free.net',
  user: 'bobatusis',
  password: 'bobatusis',
  database: 'bobatusis',
});


// Define your routes here

app.listen(3000, () => {
  console.log('Server started on port 3000');
});


// Middleware to check authentication status

// Apply the middleware to the index page route
// Middleware to check authentication status
const authenticate = (req, res, next) => {
  // Check if the user is logged in
  if (!req.session.userId) {
    // User is not logged in, redirect to the login page
    return res.redirect('/login');
  }

  // User is logged in, continue to the next middleware or route
  next();
};

// Apply the middleware to the index page route
app.get('/', authenticate, (req, res) => {
  // Render the index page
  res.render('index.ejs');
});



app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Redirect or respond to the successful authentication
    res.redirect('/dashboard');
  });


app.post('/register', (req, res) => {
  const { name, email, password } = req.body;

  // Check if all required fields are provided
  if (!name || !email || !password) {
    return res.status(400).send('All fields are required');
  }

  // Hash the password using bcrypt
  bcrypt.hash(password, 10, (hashError, hashedPassword) => {
    if (hashError) {
      console.error('Error hashing password:', hashError);
      return res.status(500).send('Internal Server Error');
    }

    // Store the user in the database
    const query = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
    pool.query(query, [name, email, hashedPassword], (queryError, results) => {
      if (queryError) {
        console.error('Error registering user:', queryError);
        return res.status(500).send('Internal Server Error');
      }

      // Registration successful
      // Redirect the user to the login page or send a success message
      // Example: redirect the user to the login page
      res.redirect('/login');
    });
  });
});

app.get('/register', (req, res) => {
  res.render('register.ejs');
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Check if the email and password are provided
  if (!email || !password) {
    return res.status(400).send('Email and password are required');
  }

  // Query the database to find the user with the provided email
  const query = 'SELECT * FROM users WHERE email = ?';
  pool.query(query, [email], (error, results) => {
    if (error) {
      console.error('Error retrieving user from database:', error);
      return res.status(500).send('Internal Server Error');
    }

    // Check if a user with the provided email exists
    if (results.length === 0) {
      return res.status(401).send('Invalid email or password');
    }

    const user = results[0];

    // Compare the provided password with the hashed password stored in the database
    bcrypt.compare(password, user.password, (bcryptError, passwordMatch) => {
      if (bcryptError) {
        console.error('Error comparing passwords:', bcryptError);
        return res.status(500).send('Internal Server Error');
      }

      // Check if the passwords match
      if (!passwordMatch) {
        return res.status(401).send('Invalid email or password');
      }

      // Authentication successful
      // Store user information in the session or generate a token as needed
      // Redirect the user to the homepage or send a success message
      // Example: store the user ID in the session and redirect to the homepage
      req.session.userId = user.id;
      res.redirect('/');
    });
  });
});


app.get('/login', (req, res) => {
  // Handle login logic here
  res.render('login.ejs');
});


app.post('/logout', (req, res) => {
  // Logout logic
  req.session.destroy();
  res.clearCookie('your-cookie-name');
  res.redirect('/login');
});

