import { JwtPayload, jwtDecode } from "jwt-decode";
import { UserData } from "../interfaces/UserData";

class AuthService {
  // Decode and return the user's profile data from the stored token
  getProfile() {
    // Retrieve the token, decode it to the UserData interface type, and return the decoded profile
    return jwtDecode<UserData>(this.getToken());
  }

  // Check if the user is logged in by verifying the presence of a valid, non-expired token
  loggedIn() {
    const token = this.getToken();
    // Return true if a token exists and is not expired
    return !!token && !this.isTokenExpired(token);
  }

  // Check if the provided token is expired by comparing the expiration time with the current time
  isTokenExpired(token: string) {
    try {
      // Decode the token, assuming it conforms to the JwtPayload type with an 'exp' (expiration) property
      const decoded = jwtDecode<JwtPayload>(token);

      // If the 'exp' property exists, check if it is in the past (token expired)
      if (decoded?.exp && decoded.exp < Date.now() / 1000) {
        return true; // Token has expired
      }
    } catch (err) {
      // If decoding fails, treat the token as invalid or expired
      return false;
    }
  }

  // Retrieve the token stored in localStorage under "id_token"
  getToken(): string {
    // Return the token if it exists, or an empty string if not found
    return localStorage.getItem("id_token") || "";
  }

  // Store the token in localStorage and redirect the user to the home page
  login(idToken: string) {
    // Save the provided token as "id_token" in localStorage
    localStorage.setItem("id_token", idToken);
    // Redirect to the home page after login
    window.location.assign("/");
  }

  // Log the user out by removing the token and redirecting to the login page
  logout() {
    // Remove the "id_token" from localStorage
    localStorage.removeItem("id_token");
    // Redirect the user to the home page after logout
    window.location.assign("/");
  }
}

export default new AuthService();
