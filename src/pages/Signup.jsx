import { useState } from "react"
import axios from "axios"
import {
  Container,
  Box,
  TextField,
  Button,
  Typography,
  Paper,
  Grid,
  IconButton,
} from "@mui/material"
import { ContentCopy, Security } from "@mui/icons-material"
import { Link } from "react-router-dom"

export default function Signup() {
  const [form, setForm] = useState({ firstName: "", lastName: "", email: "", password: "" })
  const [privateKey, setPrivateKey] = useState("")
  const [error, setError] = useState("")
  const [isLoading, setIsLoading] = useState(false)

  const baseURL = import.meta.env.VITE_APP_URL;

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value })

  const handleSignup = async (e) => {
    e.preventDefault()
    setError("")
    setIsLoading(true)
    try {
      const res = await axios.post(`${baseURL}/api/v1/user/signup`, form)
      setPrivateKey(res.data.privateKey)
    } catch (err) {
      setError(err.response?.data?.message || "Signup failed")
    } finally {
      setIsLoading(false)
    }
  }

  // Add this function inside your component
  const downloadKey = () => {
    const blob = new Blob([privateKey], { type: "application/x-pem-file" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = "private_key.pem"
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }


  const copyKey = () => {
    navigator.clipboard.writeText(privateKey)
    alert("Private key copied ✅")
  }

  return (
    <Container maxWidth="sm" sx={{ minHeight: "100vh", display: "flex", alignItems: "center" }}>
      <Paper elevation={6} sx={{ p: 5, width: "100%", borderRadius: 3 }}>
        {/* Header */}
        <Box textAlign="center" mb={4}>
          <IconButton sx={{ bgcolor: "primary.light", color: "primary.main", mb: 2 }}>
            <Security fontSize="large" />
          </IconButton>
          <Typography variant="h4" fontWeight="bold" gutterBottom>
            SecureShare
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            Signup to start sharing files securely
          </Typography>
        </Box>

        {/* Form */}
        <form onSubmit={handleSignup}>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <TextField
                label="First Name"
                name="firstName"
                value={form.firstName}
                onChange={handleChange}
                required
                fullWidth
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                label="Last Name"
                name="lastName"
                value={form.lastName}
                onChange={handleChange}
                required
                fullWidth
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                label="Email"
                name="email"
                type="email"
                value={form.email}
                onChange={handleChange}
                required
                fullWidth
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                label="Password"
                name="password"
                type="password"
                value={form.password}
                onChange={handleChange}
                required
                fullWidth
              />
            </Grid>
          </Grid>


          {error && (
            <Typography color="error" variant="body2" sx={{ mt: 2 }}>
              {error}
            </Typography>
          )}

          <Button
            type="submit"
            variant="contained"
            fullWidth
            sx={{ mt: 3, py: 1.5, fontSize: "1rem" }}
            disabled={isLoading}
          >
            {isLoading ? "Creating account..." : "Create Account"}
          </Button>
        </form>

        <Link to='/login'>already have an account? Login</Link>

        {/* Private Key Box */}
        {privateKey && (
          <Box mt={4} p={2} border="1px solid #ddd" borderRadius={2} bgcolor="grey.100">
            <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
              🔑 Your Private Key
            </Typography>
            <TextField
              multiline
              value={privateKey}
              InputProps={{ readOnly: true }}
              fullWidth
              minRows={6}
              sx={{ fontFamily: "monospace", mb: 2 }}
            />
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Button
                  variant="outlined"
                  fullWidth
                  onClick={copyKey}
                  startIcon={<ContentCopy />}
                >
                  Copy Key
                </Button>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Button
                  variant="contained"
                  color="secondary"
                  fullWidth
                  onClick={downloadKey}
                >
                  Download .PEM
                </Button>
              </Grid>
            </Grid>
          </Box>
        )}
      </Paper>
    </Container>
  )
}
