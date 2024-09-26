require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const flash = require('connect-flash');
const bcrypt = require('bcrypt');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

// MongoDB URL
const url = process.env.DB_URL;

const app = express();

// Define user schema and model
const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        unique: true,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date
});

const User = mongoose.model('User', UserSchema);

mongoose.set('strictQuery', true); // Configure strictQuery option

// Connect to MongoDB
mongoose.connect(url, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch((err) => console.error('MongoDB connection error:', err));

// Configure app
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true
}));
app.use(flash());

// Configure Nodemailer
const transporter = nodemailer.createTransport({
    service: 'Gmail', // Adjust as needed
    auth: {
        user: process.env.EMAIL_USER, // Your email address
        pass: process.env.EMAIL_PASS  // Your email password
    }
});

// Define routes
app.get('/', (req, res) => {
    const user = req.session.user;
    const message = req.flash('message')[0];
    res.render('index', { user, message });
});

app.get('/login', (req, res) => {
    const message = req.flash('message')[0];
    res.render('login', { message });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    
    User.findOne({ email }, (err, user) => {
        if (err) {
            console.error('Error during user lookup:', err);
            req.flash('message', 'An error occurred');
            return res.redirect('/login');
        }
        if (!user) {
            console.log('User not found:', email);
            req.flash('message', 'Email or password is incorrect');
            return res.redirect('/login');
        }
        
        console.log('User found:', user);
        console.log('Hashed password in DB:', user.password);
        
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                console.error('Error during password comparison:', err);
                req.flash('message', 'An error occurred');
                return res.redirect('/login');
            }
            
            if (result) {
                console.log('Password matched!');
                req.session.user = user;
                return res.redirect('/');
            } else {
                console.log('Password did not match');
                req.flash('message', 'Email or password is incorrect');
                return res.redirect('/login');
            }
        });
    });
});

app.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    console.log(`Reset password token received: ${token}`);

    User.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } }, (err, user) => {
        if (err) {
            console.error('Error during token lookup:', err);
            req.flash('message', 'An error occurred');
            return res.redirect('/forgot-password');
        }
        if (!user) {
            console.log('No user found with the provided token or token has expired');
            req.flash('message', 'Password reset token is invalid or has expired');
            return res.redirect('/forgot-password');
        }
        console.log('User found for password reset:', user.email);
        res.render('reset-password', { token, message: req.flash('message') });
    });
});

app.post('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;

    console.log(`Reset password request received for token: ${token}`);

    if (password !== confirmPassword) {
        console.log('Passwords do not match');
        req.flash('message', 'Passwords do not match');
        return res.redirect(`/reset-password/${token}`);
    }

    User.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } }, (err, user) => {
        if (err) {
            console.error('Error during token lookup:', err);
            req.flash('message', 'An error occurred');
            return res.redirect('/forgot-password');
        }
        if (!user) {
            console.log('No user found with the provided token or token has expired');
            req.flash('message', 'Password reset token is invalid or has expired');
            return res.redirect('/forgot-password');
        }

        console.log('User found, proceeding to hash new password');
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                console.error('Error during password hashing:', err);
                req.flash('message', 'An error occurred during password hashing');
                return res.redirect(`/reset-password/${token}`);
            }

            user.password = hash;
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;

            user.save()
                .then(() => {
                    console.log('Password reset successfully for user:', user.email);
                    req.flash('message', 'Password reset successfully');
                    res.redirect('/login');
                })
                .catch(err => {
                    console.error('Error saving new password:', err);
                    req.flash('message', 'Error saving new password');
                    res.redirect(`/reset-password/${token}`);
                });
        });
    });
});

app.get('/forgot-password', (req, res) => {
    const message = req.flash('message')[0];
    res.render('forgot-password', { message });
});

app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    User.findOne({ email }, (err, user) => {
        if (err) {
            req.flash('message', 'An error occurred');
            return res.redirect('/forgot-password');
        }
        if (!user) {
            req.flash('message', 'No user with that email address found');
            return res.redirect('/forgot-password');
        }
        const resetToken = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour expiry
        user.save()
            .then(() => {
                const mailOptions = {
                    to: user.email,
                    subject: 'Password Reset',
                    text: `Click here to reset your password: http://localhost:${process.env.PORT || 8000}/reset-password/${resetToken}`
                };
                transporter.sendMail(mailOptions, (error) => {
                    if (error) {
                        console.log('Error sending email: ', error);
                    } else {
                        req.flash('message', 'Password reset email sent');
                        res.redirect('/forgot-password');
                    }
                });
            })
            .catch(err => {
                req.flash('message', 'An error occurred');
                res.redirect('/forgot-password');
            });
    });
});

app.get('/signup', (req, res) => {
    const message = req.flash('message')[0];
    res.render('signup', { message });
});

app.post('/signup', (req, res) => {
    const { name, email, password, confirmpassword } = req.body;
    if (password !== confirmpassword) {
        req.flash('message', 'Passwords do not match');
        return res.redirect('/signup');
    }
    
    User.findOne({ email }, (err, user) => {
        if (err) {
            req.flash('message', 'An error occurred');
            return res.redirect('/signup');
        }
        if (user) {
            req.flash('message', 'Email already exists');
            return res.redirect('/signup');
        }

        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                req.flash('message', 'An error occurred');
                return res.redirect('/signup');
            }

            const newUser = new User({
                name,
                email,
                password: hash
            });

            newUser.save()
                .then(() => {
                    req.session.user = newUser;
                    res.redirect('/');
                })
                .catch(err => {
                    req.flash('message', 'An error occurred');
                    res.redirect('/signup');
                });
        });
    });
});

app.get('/logout', (req, res) => {
    req.session.user = undefined;
    res.redirect('/');
});

// Static pages
app.get('/home', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});
app.get('/about', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'about.html'));
});
app.get('/contact', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'contact.html'));
});

// Catch-all route for 404 errors
app.use((req, res) => {
    console.log('404 Error: Page not found');
    res.status(404).send('404: Page not found');
});

// Start the server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
