import { Request, Response, NextFunction } from "express"; // Import necessary types from express
import jwt from "jsonwebtoken"; // Import JWT for token verification

// Define an interface to type the JWT payload
interface JwtPayload {
  username: string; // JWT payload will include the username
}

// Middleware function to authenticate the JWT token
export const authenticateToken = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Extract the token from the Authorization header
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Expecting 'Bearer <token>' format

  // If there's no token in the header, respond with a 401 Unauthorized status
  if (!token) {
    return res.status(401).send("Unauthorized");
  }

  // Verify the token using the JWT secret
  jwt.verify(token, process.env.JWT_SECRET as string, (err, user) => {
    // If verification fails, respond with a 403 Forbidden status
    if (err) {
      return res.status(403).send("Forbidden");
    }

    // Check that user information is present after verification
    if (!user) {
      return res.status(401).send("Unauthorized");
    }

    // Attach the decoded user data to the request object
    req.user = user as JwtPayload;

    // Proceed to the next middleware or route handler
    next();
    return;
  });

  return;
};
