import type { UserLogin } from "../interfaces/UserLogin";

// Function to log in a user by making a POST request with login credentials
const login = async (userInfo: UserLogin) => {
  try {
    // Send a POST request to the /auth/login endpoint with the user's credentials
    const response = await fetch("/auth/login", {
      method: "POST", // Specify the request method as POST
      headers: {
        "Content-Type": "application/json", // Set the content type to JSON
      },
      body: JSON.stringify(userInfo), // Convert user information to JSON format for the request body
    });

    // Parse the JSON response from the server
    const data = await response.json();

    // Check if the response status is not OK (e.g., 4xx or 5xx)
    if (!response.ok) {
      // Throw an error if the login request failed
      throw new Error("User information not retrieved, check network tab!");
    }

    // Return the parsed data if the request was successful
    return data;
  } catch (err) {
    // Log any error that occurs during the request
    console.log("Error from user login: ", err);

    // Reject the promise with an error message if the request fails
    return Promise.reject("Could not fetch user info");
  }
};

export { login };
