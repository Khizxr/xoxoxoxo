// src/api/client.js
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:5000", // adjust if backend runs elsewhere
  headers: {
    "Content-Type": "application/json",
  },
});

// Attach JWT from localStorage to every request
api.interceptors.request.use(
  (config) => {
    try {
      const token = window.localStorage.getItem("access_token");
      if (token) {
        config.headers = config.headers || {};
        config.headers.Authorization = `Bearer ${token}`;
      }
    } catch (err) {
      // localStorage may not be available in some environments
      console.warn("Could not read access_token from localStorage", err);
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Log out on 401-like responses (for now just log and clear token)
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      console.warn("Received 401 from API, clearing token");
      try {
        window.localStorage.removeItem("access_token");
      } catch (err) {
        console.warn("Could not clear access_token from localStorage", err);
      }
    }
    return Promise.reject(error);
  }
);

export default api;
