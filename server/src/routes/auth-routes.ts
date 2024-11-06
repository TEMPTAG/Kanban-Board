import { Router, Request, Response } from "express";
import { User } from "../models/user.js"; // Import the User model
import jwt from "jsonwebtoken"; // Import JWT for generating tokens
import bcrypt from "bcrypt"; // Import bcrypt for password hashing and comparison

// Define the login function to handle user authentication
export const login = async (req: Request, res: Response) => {
  // Extract username and password from the request body
  const { username, password } = req.body;

  try {
    // Attempt to find a user with the specified username in the database
    const user = await User.findOne({ where: { username } });

    // If no user is found, respond with a 404 Not Found status
    if (!user) {
      return res.status(404).send("User not found");
    }

    // Compare the provided password with the hashed password in the database
    const validPassword = await bcrypt.compare(password, user.password);

    // If the password does not match, respond with a 401 Unauthorized status
    if (!validPassword) {
      return res.status(401).send("Invalid credentials");
    }

    // Generate a JWT token with the username as payload and a 1-hour expiration
    const token = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET as string, // Secret key from .env for signing the token
      { expiresIn: "1h" } // Set token expiration to 1 hour
    );

    // Send the generated token as a JSON response
    return res.status(200).json({ token });
  } catch (error) {
    // Catch any unexpected errors and respond with a 500 Internal Server Error status
    return res.status(500).send("Internal server error");
  }
};

// Initialize a new router instance
const router = Router();

// Define the POST route for /login that uses the login function for user authentication
router.post("/login", login);

// Export the router to be used in other parts of the application
export default router;
