// firebase.js
import dotenv from "dotenv";
import { initializeApp } from "firebase/app";
import { 
    getAuth, 
    GithubAuthProvider, 
    GoogleAuthProvider, 
    signInWithEmailAndPassword, 
    createUserWithEmailAndPassword
} from "firebase/auth";

dotenv.config();

// Config pulled from .env
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID,
  measurementId: process.env.FIREBASE_MEASUREMENT_ID,
};

// Initialize app
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

// Providers
const githubProvider = new GithubAuthProvider();
const googleProvider = new GoogleAuthProvider();

// Export the new functions
export { 
    auth, 
    githubProvider, 
    googleProvider, 
    signInWithEmailAndPassword, 
    createUserWithEmailAndPassword 
};
