import { Router, Request, Response } from "express";
import { User } from "../models/user.js"; // Import the User model
import jwt from "jsonwebtoken"; // Import JWT for generating tokens
import bcrypt from "bcrypt"; // Import bcrypt for password hashing and comparison

// Define the login function to handle user authentication
export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  const user = await User.findOne({
    where: { username },
  });
  if (!user) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  const passwordIsValid = await bcrypt.compare(password, user.password);
  if (!passwordIsValid) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  const secretKey = process.env.JWT_SECRET_KEY || "";

  const token = jwt.sign({ username }, secretKey, { expiresIn: "1h" });
  return res.json({ token });
};

// Initialize a new router instance
const router = Router();

// Define the POST route for /login that uses the login function for user authentication
router.post("/login", login);

// Export the router to be used in other parts of the application
export default router;
