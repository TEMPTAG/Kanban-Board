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
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];

    const secretKey = process.env.JWT_SECRET_KEY || "";

    jwt.verify(token, secretKey, (err, user) => {
      if (err) {
        return res.sendStatus(403); // Forbidden
      }

      req.user = user as JwtPayload;
      return next();
    });
  } else {
    res.sendStatus(401); // Unauthorized
  }
};
