require("dotenv").config();
const jwt = require("jsonwebtoken");
const CryptoJS = require("crypto-js");

// Secret keys (store securely, e.g., in .env)
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";
const ENCRYPTION_SECRET = process.env.ENCRYPTION_SECRET || "your_encryption_secret";

const encrypt = (payload) => {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
  return CryptoJS.AES.encrypt(token, ENCRYPTION_SECRET).toString();
};

const decrypt = (token) => {
  try {
    const bytes = CryptoJS.AES.decrypt(token, ENCRYPTION_SECRET);
    const decryptedToken = bytes.toString(CryptoJS.enc.Utf8);
    return jwt.verify(decryptedToken, JWT_SECRET);
  } catch (error) {
    return { error: "Invalid or expired token" };
  }
};

// Let's Testing the implementation of users inside the script.js itself :->

const userData = { id: 1, username: "test_user" };

const encryptedToken = encrypt(userData);
console.log("Encrypted Token:", encryptedToken);

const decryptedData = decrypt(encryptedToken);
console.log("Decrypted Data:", decryptedData);

if (!decryptedData.error) {
  console.log("✅ Success");
} else {
  console.log("❌ Failed");
}

module.exports = {
  encrypt,
  decrypt,
};
