const userModel = require("../models/userModel");

const bcrypt = require('bcrypt');

const loginController = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    
    // Retrieve the user from the database based on the provided email
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.status(404).send("User Not Found");
    }

    // Compare the hashed password stored in the database with the password provided in the request
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).send("Incorrect Password");
    }

    // If passwords match, the user is authenticated
    res.status(200).json({
      success: true,
      user,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error,
    });
  }
};

const registerController = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user instance with the hashed password
    const newUser = new userModel({
      name,
      email,
      password: hashedPassword, // Store the hashed password in the database
    });

    // Save the user to the database
    await newUser.save();

    // Respond with a success message
    res.status(201).json({
      success: true,
      newUser,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error,
    });
  }
};

module.exports = { loginController, registerController };
