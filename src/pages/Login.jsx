import { useState } from "react";
import axios from "axios";
import {
  Container,
  Box,
  TextField,
  Button,
  Typography,
  Paper,
  IconButton,
} from "@mui/material";
import { Lock } from "@mui/icons-material";
import { Link, useNavigate } from "react-router-dom";


async function signChallenge(privateKeyPem, challenge) {

  if (!challenge) throw new Error("Challenge is empty");
  if (!privateKeyPem) throw new Error("Private key is empty");

  try {

    const pemContents = privateKeyPem
      .replace(/-----BEGIN PRIVATE KEY-----/, "")
      .replace(/-----END PRIVATE KEY-----/, "")
      .replace(/\r?\n|\r/g, "");

    const binaryDer = Uint8Array.from(atob(pemContents), (c) =>
      c.charCodeAt(0)
    );

    const key = await window.crypto.subtle.importKey(
      "pkcs8",
      binaryDer.buffer,
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signature = await window.crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 },
      key,
      new TextEncoder().encode(challenge)
    );

    const bytes = new Uint8Array(signature);
    let binary = "";
    bytes.forEach((b) => (binary += String.fromCharCode(b)));
    return btoa(binary);
  } catch (error) {
    console.error("Error in signChallenge:", error);
    throw new Error("Failed to sign challenge: " + error.message);
  }
}


export default function Login() {
  const [form, setForm] = useState({
    email: "",
    password: "",
    privateKey: ""
  });
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const baseURL = import.meta.env.VITE_APP_URL;

  const handleChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  const getChallenge = async () => {
    const res = await axios.get(`${baseURL}/get-challenge`, {
      withCredentials: true,
    });
    return res.data.challenge;
  };

  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    try {
      const challenge = await getChallenge();

      const signedChallenge = await signChallenge(form.privateKey, challenge);

      const res = await axios.post(
        `${baseURL}/api/v1/user/login`,
        {
          email: form.email,
          password: form.password,
          signedChallenge
        },
        { withCredentials: true }
      );
      localStorage.setItem("token", res.data.token);
      localStorage.setItem("privateKey", form.privateKey);
      localStorage.setItem("email", form.email);

      navigate("/");
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.message || "Login failed");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Container
      maxWidth="sm"
      sx={{ minHeight: "100vh", display: "flex", alignItems: "center" }}
    >
      <Paper elevation={6} sx={{ p: 5, width: "100%", borderRadius: 3 }}>
        <Box textAlign="center" mb={4}>
          <IconButton
            sx={{ bgcolor: "primary.light", color: "primary.main", mb: 2 }}
          >
            <Lock fontSize="large" />
          </IconButton>
          <Typography variant="h4" fontWeight="bold" gutterBottom>
            SecureShare
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            Login using your email and private key
          </Typography>
        </Box>

        <form onSubmit={handleLogin}>
          <TextField
            label="Email"
            name="email"
            type="email"
            value={form.email}
            onChange={handleChange}
            required
            fullWidth
            sx={{ mb: 3 }}
          />
          <TextField
            label="Password"
            name="password"
            type="password"
            value={form.password}
            onChange={handleChange}
            required
            fullWidth
            sx={{ mb: 3 }}
          />
          <TextField
            label="Private Key"
            name="privateKey"
            multiline
            minRows={6}
            value={form.privateKey}
            onChange={handleChange}
            required
            fullWidth
            sx={{ fontFamily: "monospace", mb: 3 }}
          />

          {error && (
            <Typography color="error" variant="body2" sx={{ mb: 2 }}>
              {error}
            </Typography>
          )}

          <Button
            type="submit"
            variant="contained"
            fullWidth
            sx={{ py: 1.5, fontSize: "1rem" }}
            disabled={isLoading}
          >
            {isLoading ? "Signing in..." : "Login"}
          </Button>
        </form>
        <Link to="/signup">Or Signup</Link>
      </Paper>
    </Container>
  );
}
