import { useState, useEffect } from "react";
import {
  AppBar, Toolbar, Typography, Button, Container, Grid, Card,
  CardContent, CardHeader, Tabs, Tab, Box, Dialog, DialogTitle,
  DialogContent, DialogActions, TextField, List, ListItem,
  ListItemText, CircularProgress, Input
} from "@mui/material";
import { Logout, Visibility, Download, Share, Shield } from "@mui/icons-material";
import { useNavigate } from "react-router-dom";
import axios from "axios";

export default function Dashboard() {
  const [files, setFiles] = useState([]);
  const [tab, setTab] = useState(0);
  const [selectedFile, setSelectedFile] = useState(null);
  const [decryptedPreview, setDecryptedPreview] = useState("");
  const [openSendDialog, setOpenSendDialog] = useState(false);
  const [users, setUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [recipient, setRecipient] = useState(null);
  const [openFileDialog, setOpenFileDialog] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [receivedFiles, setReceivedFiles] = useState([]);
  const navigate = useNavigate();
  const baseURL = import.meta.env.VITE_APP_URL;

  useEffect(() => {
    fetchReceivedFiles();
  }, []);

  async function handleDownload(file) {
    try {
      console.log("Downloading file:", file.filename);

      // 1. Load private key from localStorage
      const privateKeyPem = localStorage.getItem("privateKey");
      if (!privateKeyPem) {
        alert("You must import your private key first!");
        return;
      }

      // Convert PEM to ArrayBuffer
      function pemToArrayBuffer(pem) {
        const b64 = pem.replace(/-----BEGIN PRIVATE KEY-----/, "")
          .replace(/-----END PRIVATE KEY-----/, "")
          .replace(/\s+/g, "");
        const binary = atob(b64);
        const buffer = new ArrayBuffer(binary.length);
        const view = new Uint8Array(buffer);
        for (let i = 0; i < binary.length; i++) view[i] = binary.charCodeAt(i);
        return buffer;
      }

      const privateKey = await window.crypto.subtle.importKey(
        "pkcs8",
        pemToArrayBuffer(privateKeyPem),
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"]
      );

      console.log("Private key imported");

      // 2. Decrypt the AES key
      const encryptedAESKeyBytes = Uint8Array.from(atob(file.encryptedAESKey), c => c.charCodeAt(0));

      const aesKeyRaw = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedAESKeyBytes
      );

      console.log("AES key decrypted");

      const aesKey = await window.crypto.subtle.importKey(
        "raw",
        aesKeyRaw,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      // 3. Download encrypted file via presigned URL
      const fileRes = await fetch(file.presignedUrl);
      const encryptedFileArrayBuffer = await fileRes.arrayBuffer();

      console.log("Encrypted file downloaded", encryptedFileArrayBuffer.byteLength);

      // 4. Decrypt file using AES-GCM
      const iv = Uint8Array.from(atob(file.iv), c => c.charCodeAt(0));

      const decryptedArrayBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        aesKey,
        encryptedFileArrayBuffer
      );

      console.log("File decrypted!");

      // 5. Trigger browser download
      const blob = new Blob([decryptedArrayBuffer]);
      const url = URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = file.filename;
      document.body.appendChild(a);
      a.click();
      a.remove();

      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Download error:", err);
      alert("Failed to decrypt or download file (see console)");
    }
  }

  async function handlePreview(file) {
    const token = localStorage.getItem("token");

    const previewUrl = `${baseURL}/api/v1/file/preview/${file.id}?token=${token}`;

    // open in new tab
    window.open(previewUrl, "_blank");
  }



  async function fetchReceivedFiles() {
    try {
      const token = localStorage.getItem("token");
      const res = await axios.get(`${baseURL}/api/v1/file/received`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      setReceivedFiles(res.data.data);
    } catch (err) {
      console.error("Failed to load received files:", err);
    }
  }

  useEffect(() => {
    setFiles([
      {
        id: 1,
        name: "report.pdf",
        size: 102400,
        uploadedBy: "me",
        uploadedAt: new Date().toISOString(),
        encryptedAESKey: "xxxx...",
        iv: "yyyy...",
        encryptedData: "zzzz...",
      },
    ]);
  }, []);

  const formatSize = (bytes) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/signup");
  };

  const handleOpenSendDialog = async () => {
    setOpenSendDialog(true);
    setLoadingUsers(true);
    try {
      const res = await axios.get(`${baseURL}/api/v1/user/users`);
      setUsers(res.data.data);
    } catch (error) {
      console.error("Failed to fetch users", error);
    } finally {
      setLoadingUsers(false);
    }
  };

  // --- Crypto helpers ---
  async function encryptFile(file, recipientPublicKeyPem) {
    try {
      console.log("Starting encryption for file:", file.name);

      // 1. Generate AES key
      const aesKey = crypto.getRandomValues(new Uint8Array(32)); // 256-bit key
      const iv = crypto.getRandomValues(new Uint8Array(16));
      console.log("Generated AES key (raw):", aesKey);
      console.log("Generated IV:", iv);

      // 2. Import AES key
      const aesCryptoKey = await window.crypto.subtle.importKey(
        "raw",
        aesKey,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );
      console.log("AES key imported:", aesCryptoKey);

      // 3. Read file data
      const fileBuffer = await file.arrayBuffer();
      console.log("File buffer length:", fileBuffer.byteLength);

      // 4. Encrypt file with AES
      const encryptedData = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesCryptoKey,
        fileBuffer
      );
      console.log("AES encrypted file length:", encryptedData.byteLength);

      // 5. Import recipient public key
      console.log("Recipient PEM:", recipientPublicKeyPem);
      const publicKeyBuffer = pemToArrayBuffer(recipientPublicKeyPem);
      console.log("Converted PEM to ArrayBuffer:", publicKeyBuffer.byteLength);

      const publicKey = await window.crypto.subtle.importKey(
        "spki",
        publicKeyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );
      console.log("Public key imported:", publicKey);

      // 6. Encrypt AES key with recipient’s RSA public key
      const encryptedAESKey = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        aesKey
      );
      console.log("Encrypted AES key length:", encryptedAESKey.byteLength);

      return {
        encryptedAESKey: arrayBufferToBase64(encryptedAESKey),
        iv: arrayBufferToBase64(iv),
        encryptedData: arrayBufferToBase64(encryptedData),
      };
    } catch (err) {
      console.error("Encryption error inside encryptFile:", err);
      throw err; // rethrow so caller sees it
    }
  }

  function pemToArrayBuffer(pem) {
    console.log("Converting PEM to ArrayBuffer...");
    const b64 = pem
      .replace(/-----BEGIN PUBLIC KEY-----/, "")
      .replace(/-----END PUBLIC KEY-----/, "")
      .replace(/\s+/g, "");
    console.log("Base64 from PEM:", b64.substring(0, 50) + "...");
    const binaryDer = atob(b64);
    const buffer = new ArrayBuffer(binaryDer.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binaryDer.length; i++) {
      view[i] = binaryDer.charCodeAt(i);
    }
    console.log("ArrayBuffer length after PEM conversion:", buffer.byteLength);
    return buffer;
  }

  function arrayBufferToBase64(buffer) {
    console.log("Converting ArrayBuffer to Base64, length:", buffer.byteLength);
    let binary = "";
    const bytes = new Uint8Array(buffer);
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(
        null,
        bytes.subarray(i, i + chunk)
      );
    }
    return btoa(binary);
  }

  async function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file || !recipient) return;

    setUploading(true);
    try {
      const { encryptedAESKey, iv, encryptedData } = await encryptFile(file, recipient.publicKey);
      // send to backend
      const token = localStorage.getItem("token");
      const res = await axios.post(`${baseURL}/api/v1/file/send`, {
        filename: file.name,
        encryptedData, // base64
        iv, // base64
        encryptedAESKey, // base64
        recipientEmail: recipient.email,
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });

      console.log("Backend response:", res.data);
      alert("File sent successfully!");
    } catch (err) {
      console.error("Encryption / upload failed:", err);
      alert("Encryption or upload failed — check console.");
    } finally {
      setUploading(false);
      setOpenFileDialog(false);
    }
  }


  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "#f9fafb" }}>
      {/* Header */}
      <AppBar position="static" color="default" elevation={1}>
        <Toolbar sx={{ display: "flex", justifyContent: "space-between" }}>
          <Box display="flex" alignItems="center" gap={1}>
            <Shield color="primary" />
            <Box>
              <Typography variant="h6" fontWeight="bold">
                SecureShare
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Welcome, {localStorage.getItem("email")}
              </Typography>
            </Box>
          </Box>
          <Button
            variant="outlined"
            startIcon={<Logout />}
            color="error"
            onClick={handleLogout}
          >
            Logout
          </Button>
        </Toolbar>
      </AppBar>

      {/* Tabs */}
      <Container sx={{ py: 4 }}>
        <Tabs value={tab} onChange={(e, newValue) => setTab(newValue)} centered>
          <Tab label="My Files" />
          <Tab label="Access Logs" />
          <Tab label="Send File" />
        </Tabs>

        {/* My Files */}
        {tab === 0 && (
          <Grid container spacing={3} sx={{ mt: 2 }}>

            {receivedFiles.length === 0 && (
              <Typography textAlign="center" width="100%" color="text.secondary">
                No files shared with you yet.
              </Typography>
            )}

            {receivedFiles.map((file) => (
              <Grid item xs={12} sm={6} md={4} key={file._id}>
                <Card sx={{ borderRadius: 3, boxShadow: 3 }}>
                  <CardHeader
                    title={file.filename}
                    subheader={`Sender: ${file.senderEmail}`}
                    avatar={<Shield color="primary" />}
                  />
                  <CardContent>
                    <Typography variant="body2" color="text.secondary">
                      Expires on: {new Date(file.expiresAt).toLocaleDateString()}
                    </Typography>

                    <Box mt={2} display="flex" gap={1}>
                      <Button
                        variant="outlined"
                        size="small"
                        startIcon={<Download />}
                        onClick={() => handleDownload(file)}
                      >
                        Download
                      </Button>

                      <Button
                        variant="outlined"
                        size="small"
                        startIcon={<Visibility />}
                        onClick={() => handlePreview(file)}
                      >
                        Preview
                      </Button>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}

          </Grid>
        )}


        {/* Access Logs */}
        {tab === 1 && (
          <Box mt={4}>
            <Typography variant="h6">Access Logs</Typography>
            <Typography variant="body2" color="text.secondary">
              (You can render a table of file actions here)
            </Typography>
          </Box>
        )}

        {/* Send File Section */}
        {tab === 2 && (
          <Box mt={4} textAlign="center">
            <Typography variant="h6" gutterBottom>
              Send Files Securely
            </Typography>
            <Button variant="contained" onClick={handleOpenSendDialog}>
              Choose Recipient
            </Button>
          </Box>
        )}
      </Container>

      {/* Send File Dialog (User list) */}
      <Dialog open={openSendDialog} onClose={() => setOpenSendDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Select Recipient</DialogTitle>
        <DialogContent dividers>
          {loadingUsers ? (
            <CircularProgress />
          ) : (
            <List>
              {users.map((u) => (
                <ListItem
                  button
                  key={u.email}
                  onClick={() => {
                    setRecipient(u);
                    setOpenSendDialog(false);
                    setOpenFileDialog(true);
                  }}
                >
                  <ListItemText
                    primary={u.email}
                    secondary={u.publicKey.substring(0, 40) + "..."}
                  />
                </ListItem>
              ))}
              {users.length === 0 && <Typography>No users found</Typography>}
            </List>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenSendDialog(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* File Upload Dialog */}
      <Dialog open={openFileDialog} onClose={() => setOpenFileDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Upload File for {recipient?.email}</DialogTitle>
        <DialogContent dividers>
          <Input
            type="file"
            fullWidth
            onChange={handleFileUpload}
            disabled={uploading}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenFileDialog(false)}>Cancel</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
