
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;


mongoose.connect('your-mongodb-uri', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Error connecting to MongoDB:', err));


app.use(express.json());
app.use(cors());


const User = mongoose.model('User', new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
}));


const generateToken = (user) => {
  return jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
};


app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.json({ success: true });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ success: false, message: 'Registration failed.' });
  }
});


app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      res.status(401).json({ success: false, message: 'Invalid email or password.' });
      return;
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      res.status(401).json({ success: false, message: 'Invalid email or password.' });
      return;
    }

    const token = generateToken(user);
    res.json({ success: true, token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ success: false, message: 'Login failed.' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
