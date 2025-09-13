// ===================================
// boxService.js
// Box.com API integration
// ===================================

import "dotenv/config";
import BoxSDK from "box-node-sdk";

// Initialize the Box SDK
let sdk;

function initializeBoxClient() {
  const BOX_ACCESS_TOKEN = process.env.BOX_ACCESS_TOKEN;
  if (!BOX_ACCESS_TOKEN) {
    console.error("⚠️ BOX_ACCESS_TOKEN is not set in the environment variables.");
    throw new Error("Box authentication token not found.");
  }

  sdk = new BoxSDK({
    boxClientId: 'YOUR_CLIENT_ID', // Replace with your Box App's Client ID
    boxClientSecret: 'YOUR_CLIENT_SECRET' // Replace with your Box App's Client Secret
  });

  const client = sdk.getOAuth2Client(BOX_ACCESS_TOKEN);
  return client;
}

export async function createUserFolder(username) {
  try {
    const client = initializeBoxClient();
    console.log(`Attempting to create Box folder for user: ${username}`);
    const response = await client.folders.create("0", username);
    console.log("✅ Box folder created successfully:", response.name);
    return response;
  } catch (error) {
    console.error("Error creating user folder on Box.com:", error.message);
    return null; 
  }
}