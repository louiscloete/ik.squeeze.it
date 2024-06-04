import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import bcrypt from 'bcrypt';
import session from 'express-session'; //For managing sessions
import passport from 'passport'; //Add authentication strategies
import { Strategy } from 'passport-local'; //Using local login strategy
import env from 'dotenv'; 
import { nanoid } from 'nanoid';

const app = express();
env.config(); //Initialize dotenv adding .env file to process
const port = process.env.SERVER_PORT;
const host = process.env.SERVER_HOST;
const server = host + port + '/';
const saltRounds = 10;

//Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

//P1
app.use(
  session({
    secret: process.env.SESSION_SECRET, //Tap into node.js process -> env (environment variable property) -> variable name
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // One day length cookie
    },
  })
);

//Passport module used after initialization of a session
//P2
app.use(passport.initialize());
//P3
app.use(passport.session());

//Establish the connection with the database
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

db.connect();

//Retrieve user profile in the form of an array containing an object
async function getUserProfile(currentUserId) {
  try{
    const result = await db.query(
      'SELECT users.id, users.email, url_list.url_card_id, url_list.title, url_list.url, url_list.short_url FROM users INNER JOIN url_list ON users.id = url_list.user_id WHERE users.id = $1 ORDER BY url_list.url_card_id DESC;',
      [currentUserId]
    );
    const userProfile = result.rows;
    return userProfile;
  }
  catch(error){
    console.log("Error getting user profile: ",error);
  }
}

//Retrieve user information, returning an object containing an object with the user information and an array with the URL cards.
async function readUserInfo(currentUserId) {
  try {
    const result = await db.query('SELECT * FROM users WHERE id = $1;', [
      currentUserId,
    ]);
    const userInfo = {
      currentUserId: result.rows[0].id,
      userName: result.rows[0].email,
      firstname: result.rows[0].firstname,
      lastname: result.rows[0].lastname,
    };
    const userProfile = await getUserProfile(userInfo.currentUserId);
    return { userInfo, userProfile };
  } catch (error) {
    console.log('Could not find user information: ', error);
  }
}

app.get('/', (req, res) => {
  req.session.messages = [];
  res.render('home.ejs');
});

app.get('/login', async (req, res) => {
  if (req.isAuthenticated()) {
    //Check if user in current session is logged in
    //req.user is an object with key value pairs of authenticated set by passport
    const currentUserId = req.user.id;
    const result = await readUserInfo(currentUserId);
 
    res.render('user_urls.ejs', {
      //Load the dashboard page if already logged in
      userInfo: result.userInfo, //An object with the user information from the user table. We do not want to send duplicate information in the array below. Size vs query time
      userProfile: result.userProfile, //An array with the user profile from user_list. The array contains an object with the cards.
      server: server, //To allow copy functionality via evironmental variable
    });
  } else {
    if(req.query.error){
      const messages = [req.query.error];
      res.render('login.ejs', {messages: messages});  //Registration duplicated email error. Server side validation
    } else {
      res.render('login.ejs', {messages: req.session.messages}); //Login failure. Server side validation
    }
  }
});

app.get('/register', (req, res) => {
  res.render('register.ejs');
});

//Route for redirection when short url received
app.get('/gt/:id', async (req, res) => {
  const requestedUrl = 'gt/' + req.params.id;
  //Get full url from the database and redirect
  const result = await db.query(
    'SELECT url FROM url_list WHERE short_url = $1;',
    [requestedUrl]
  );
  res.redirect(result.rows[0].url);
});

app.get('/logout', (req, res) => {
  req.logout((error) => {
    if (error) console.log('Error logging out: ', error);
    res.redirect('/');
  });
});


app.get('/user_urls', async (req, res) => {
  if (req.isAuthenticated()) { 
    const currentUserId = req.user.id;
    const result = await readUserInfo(currentUserId);
 
    res.render('user_urls.ejs', {
      userInfo: result.userInfo, 
      userProfile: result.userProfile, 
      server: server,
    });
  } else {
    res.redirect('/login');
  }
});

app.post('/editUser', async (req, res) => {
  const currentUserId = req.body.userId;
  const result = await readUserInfo(currentUserId);
  res.render('editUser.ejs', {
    userInfo: result.userInfo, 
    userProfile: result.userProfile,
  });
});

//P7
//Use passport as middleware to handle login when the login route is called up
app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/user_urls',
    failureRedirect: '/login',
    failureMessage: 'Incorrect username or password, or not registered', //For server side validation
  })
);

app.post('/register', async (req, res) => {
  //Submitting the registration form
  const firstname = req.body.firstname;
  const lastname = req.body.lastname;
  const email = req.body.username; 
  const password = req.body.password;

  try {
    const checkResult = await db.query('SELECT * FROM users WHERE email = LOWER($1);', [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      const reason = encodeURIComponent('Email already exists, please log in');
      res.redirect('/login?error='+reason); //pass error to get /login
    } else {
      //Hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          //If there is an error with the hashing
          console.error('Error hashing password:', err);
        } else {
          //Add the cridentials to the database and return the user added
          const result = await db.query(
            'INSERT INTO users (firstname, lastname, email, password) VALUES ($1, $2, $3, $4) RETURNING *',
            [firstname, lastname, email.toLowerCase(), hash]
          );
          const user = result.rows[0];
          req.login(user, (error) => {
            //Passport adds a login method, we want to redirect the user to the dashboard
            if (error) {
              return next(err);
            }
            return res.redirect('/user_urls');
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post('/add', async (req, res) => {
  const randomURL = nanoid(8);
  const newTitle = req.body.newUrlTitle;
  const newUrl = req.body.newUrl;
  const shortUrl = 'gt/' + randomURL;
  const currentUserId = req.body.userId;
  try {
    await db.query(
      'INSERT INTO url_list (title,url,short_url,user_id) VALUES ($1,$2,$3,$4)',
      [newTitle, newUrl, shortUrl, currentUserId]
    );
    const result = await readUserInfo(currentUserId);
    res.render('user_urls.ejs', {
      //load the dashboard page if already logged in
      userInfo: result.userInfo,
      userProfile: result.userProfile,
      server: server,
    });
  } catch (error) {
    console.log('Error inserting data into database: ', error);
  }
});

app.post('/delete', async (req, res) => {
  const deleteCardId = req.body.deleteCardId;
  try {
    const userIdResult = await db.query(
      'DELETE FROM url_list WHERE url_card_id = $1 RETURNING user_id;',
      [deleteCardId]
    );
    const currentUserId = userIdResult.rows[0].user_id;
    const result = await readUserInfo(currentUserId);
    res.render('user_urls.ejs', {
      userInfo: result.userInfo,
      userProfile: result.userProfile,
      server: server,
    });
  } catch (error) {
    console.log('Error deleting record: ', error);
  }
});

app.post('/edit', async (req, res) => {
  const updatedCardTitle = req.body.updatedCardTitle;
  const updatedCardUrl = req.body.updatedCardUrl;
  const editCardId = req.body.editCardId; 
  try {
    const userIdResult = await db.query(
      'UPDATE url_list SET title = $1, url = $2 WHERE url_card_id = $3 RETURNING user_id;',
      [updatedCardTitle, updatedCardUrl, editCardId]
    );
    const currentUserId = userIdResult.rows[0].user_id;
    const result = await readUserInfo(currentUserId);
    res.render('user_urls.ejs', {
      userInfo: result.userInfo,
      userProfile: result.userProfile,
      server: server,
    });
  } catch (error) {
    console.log('Error occured while doing update: ', error);
  }
});

app.post('/updateUser', async (req, res) => {
  const currentUserId = req.body.userId;
  const firstname = req.body.firstname;
  const lastname = req.body.lastname;
  const email = req.body.username; 
  if (req.body.password) { // A new password has been entered and we need to go through bcrypt and passport
    const password = req.body.password;
    try {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error('Error hashing password:', err);
        } else {
          const result = await db.query(
            'UPDATE users SET firstname = $1, lastname = $2, email = $3, password = $4 WHERE id = $5 RETURNING *',
            [firstname, lastname, email.toLowerCase(), hash, currentUserId]
          );
          const user = result.rows[0];
          req.login(user, async (error) => {
            if (error) {
              return next(err);
            }
            const result = await readUserInfo(currentUserId);
            return res.redirect('/user_urls');
          });
        }
      });
    } catch (err) {
      console.log(err);
    }
  } else {
    // No new password entered
    try {
      const result = await db.query(
        'UPDATE users SET firstname = $1, lastname = $2, email = $3 WHERE id = $4 RETURNING *;',
        [firstname, lastname, email, currentUserId]
      );
      const user = result.rows[0];
      req.login(user, async (error) => {
        if (error) {
          return next(err);
        }
        const result = await readUserInfo(currentUserId);
        return res.redirect('/user_urls');
      });
    } catch (err) {
      console.log(err);
    }
  }
});

//P4
passport.use(
  new Strategy(async function verify(username, password, cb) {
    //Username and password picked up from login form
    try {
      const result = await db.query('SELECT * FROM users WHERE email = LOWER($1) ', [
        username,
      ]);
      if (result.rows.length > 0) {
        // Are there any matches for the email if yes, lets use it
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (error, result) => {
          // Compare hashed password from db with login password
          if (error) {
            return cb(error); //An error happend with the comparrison
          } else {
            if (result) {
              return cb(null, user); //Return callback with no errors and include user info when redirecting to dahsboard
            } else {
              return cb(null, false); //Result is false meaning incorrect password was entered
            }
          }
        });
      } else {
        return cb(null, false); //Ask to login
      }
    } catch (error) {
      console.log(err);
    }
  })
);

//P5
//Save data of user that logged in to local storage/session
passport.serializeUser((user, cb) => {
  cb(null, user);
});

//P6
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port} yay!`);
});
