// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyCf48K-TS32ZL047_iLGFrGNRbjvAnrLAY",
  authDomain: "everleaf-30e5d.firebaseapp.com",
  projectId: "everleaf-30e5d",
  storageBucket: "everleaf-30e5d.firebasestorage.app",
  messagingSenderId: "452083961396",
  appId: "1:452083961396:web:1e1810d00d07f93a0c0461",
  measurementId: "G-3BS5B9R7NK"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);
