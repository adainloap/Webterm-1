import { initializeApp } from "https://www.gstatic.com/firebasejs/10.3.1/firebase-app.js";
import { 
  getAuth, 
  GithubAuthProvider, 
  GoogleAuthProvider, 
  OAuthProvider, 
  signInWithPopup 
} from "https://www.gstatic.com/firebasejs/10.3.1/firebase-auth.js";

// IMPORTANT: Do not hardcode API keys. Use environment variables in your backend.
const firebaseConfig = {
  apiKey: "AIzaSyDz30MLY_ffYF6QZbigcbNFCl-MuiCtFXw",
  authDomain: "webterminal-8489.firebaseapp.com",
  projectId: "webterminal-8489",
  storageBucket: "webterminal-8489.firebasestorage.app",
  messagingSenderId: "1043265310244",
  appId: "1:1043265310244:web:9280f96cdae72bbdec12b1"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

const githubProvider = new GithubAuthProvider();
const googleProvider = new GoogleAuthProvider();
const microsoftProvider = new OAuthProvider("microsoft.com");

// ============================
// GitHub login
// ============================
export async function loginWithGitHub() {
  try {
    const result = await signInWithPopup(auth, githubProvider);

    const credential = GithubAuthProvider.credentialFromResult(result);
    const token = credential.accessToken;

    const ghRes = await fetch("https://api.github.com/user", {
      headers: { Authorization: `token ${token}` }
    });
    const ghProfile = await ghRes.json();

    const email = ghProfile.email || result.user.email || null;
    const username = ghProfile.login || result.user.displayName || "GitHubUser";

    const response = await fetch("/api/social-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        uid: ghProfile.id,
        email: email,
        displayName: username
      })
    });

    const data = await response.json();
    if (data.success) {
      window.location.href = "/terminal";
    } else {
      window.showMessage(data.message || "Login failed");
    }
  } catch (error) {
    console.error("GitHub login error:", error);
    window.showMessage("GitHub login failed: " + error.message);
  }
}

// ============================
// Google login
// ============================
export async function loginWithGoogle() {
  try {
    const result = await signInWithPopup(auth, googleProvider);
    const user = result.user;

    const response = await fetch("/api/social-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        uid: user.uid,
        email: user.email || null,
        displayName: user.displayName || "GoogleUser"
      })
    });

    const data = await response.json();
    if (data.success) {
      window.location.href = "/terminal";
    } else {
      window.showMessage(data.message || "Login failed");
    }
  } catch (error) {
    console.error("Google login error:", error);
    window.showMessage("Google login failed: " + error.message);
  }
}

// ============================
// Microsoft login
// ============================
export async function loginWithMicrosoft() {
  try {
    const result = await signInWithPopup(auth, microsoftProvider);
    const user = result.user;

    const response = await fetch("/api/social-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        uid: user.uid,
        email: user.email || null,
        displayName: user.displayName || "MicrosoftUser"
      })
    });

    const data = await response.json();
    if (data.success) {
      window.location.href = "/terminal";
    } else {
      window.showMessage(data.message || "Login failed");
    }
  } catch (error) {
    console.error("Microsoft login error:", error);
    window.showMessage("Microsoft login failed: " + error.message);
  }
}
