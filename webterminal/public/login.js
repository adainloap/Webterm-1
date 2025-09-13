// login.js
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.3.1/firebase-app.js";
import { getAuth, GithubAuthProvider, GoogleAuthProvider, signInWithPopup } from "https://www.gstatic.com/firebasejs/10.3.1/firebase-auth.js";

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

// GitHub login
export async function loginWithGitHub() {
  try {
    const result = await signInWithPopup(auth, githubProvider);
    const user = result.user;

    const response = await fetch("/api/social-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        uid: user.uid,
        email: user.email,
        displayName: user.displayName
      })
    });

    const data = await response.json();
    if (data.success) window.location.href = "/terminal";
    else alert(data.message || "Login failed");

  } catch (error) {
    console.error("GitHub login error:", error);
    alert("GitHub login failed.");
  }
}

// Google login
export async function loginWithGoogle() {
  try {
    const result = await signInWithPopup(auth, googleProvider);
    const user = result.user;

    const response = await fetch("/api/social-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        uid: user.uid,
        email: user.email,
        displayName: user.displayName
      })
    });

    const data = await response.json();
    if (data.success) window.location.href = "/terminal";
    else alert(data.message || "Login failed");

  } catch (error) {
    console.error("Google login error:", error);
    alert("Google login failed.");
  }
}
