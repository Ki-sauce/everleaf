const User = require('../models/User');
const { generateToken, storeSession, removeSession } = require('../middleware/auth');
const crypto = require('crypto');
const admin = require('firebase-admin');
// Register new user
const signup = async (req, res) => {
  try {
    const { email, password, firstName, lastName, institution } = req.body;

    // Check if user already exists
    const existingUser = await User.findByEmail(email);
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email already exists'
      });
    }

    // Create new user
    const user = await User.create({
      email,
      password,
      firstName,
      lastName,
      institution
    });

    // Generate JWT token
    const token = generateToken(user);

    // Store session
    await storeSession(user.id, token, req.get('User-Agent'), req.ip);

    // Remove password from response
    const { password_hash, ...userResponse } = user;

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: userResponse
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create user account'
    });
  }
};

// Login user
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await User.findByEmail(email);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Check if user has a password (not OAuth user)
    if (!user.password_hash) {
      return res.status(401).json({
        success: false,
        message: 'Please sign in with Google or reset your password'
      });
    }

    // Verify password
    const isPasswordValid = await User.verifyPassword(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Update last login
    await User.updateLastLogin(user.id);

    // Generate JWT token
    const token = generateToken(user);

    // Store session
    await storeSession(user.id, token, req.get('User-Agent'), req.ip);

    // Remove password from response
    const { password_hash, ...userResponse } = user;

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: userResponse
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed'
    });
  }
};

// Admin login (separate endpoint for admin users)
const adminLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await User.findByEmail(email);
    if (!user || user.role !== 'admin') {
      return res.status(401).json({
        success: false,
        message: 'Invalid admin credentials'
      });
    }

    // Verify password
    const isPasswordValid = await User.verifyPassword(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid admin credentials'
      });
    }

    // Update last login
    await User.updateLastLogin(user.id);

    // Generate JWT 
    const token = generateToken(user);

    // Store session
    await storeSession(user.id, token, req.get('User-Agent'), req.ip);

    // Remove password from response
    const { password_hash, ...userResponse } = user;

    res.json({
      success: true,
      message: 'Admin login successful',
      token,
      user: userResponse
    });

  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({
      success: false,
      message: 'Admin login failed'
    });
  }
};

// Logout user
const logout = async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '') || req.cookies.token;
    
    if (token) {
      await removeSession(token);
    }

    res.json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Logout failed'
    });
  }
};

// Verify token
const verifyToken = async (req, res) => {
  try {
    // If we reach here, the token is valid (verified by middleware)
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        institution: user.institution,
        role: user.role,
        emailVerified: user.email_verified,
        avatarUrl: user.avatar_url
      }
    });

  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Token verification failed'
    });
  }
};

// Request password reset
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    // Find user by email
    const user = await User.findByEmail(email);
    if (!user) {
      // Don't reveal whether user exists or not
      return res.json({
        success: true,
        message: 'If an account with that email exists, we have sent a password reset link'
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hour from now

    // Save reset token to database
    await User.setResetToken(email, resetToken, resetTokenExpires);

    // TODO: Send reset email (email service not implemented)
    console.log(`Password reset token for ${email}: ${resetToken}`);

    res.json({
      success: true,
      message: 'If an account with that email exists, we have sent a password reset link'
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process password reset request'
    });
  }
};

// Reset password
const resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;

    // Find user by reset token
    const user = await User.findByResetToken(token);
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset token'
      });
    }

    // Reset password
    await User.resetPassword(user.id, password);

    res.json({
      success: true,
      message: 'Password reset successfully'
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reset password'
    });
  }
};

// Google firebase login
// Ensure Firebase Admin is initialized
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    }),
  });
}

const googleLogin = async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) {
      return res.status(400).json({ success: false, message: 'Missing idToken' });
    }

    // ✅ Verify Firebase ID token
    const decoded = await admin.auth().verifyIdToken(idToken);
    const { uid, email, name = '', picture = '' } = decoded;

    if (!uid || !email) {
      return res.status(400).json({ success: false, message: 'Invalid token payload' });
    }

    // 🧠 Parse name
    const [firstName, ...rest] = name.trim().split(' ');
    const lastName = rest.join(' ') || '';

    // 🔍 Check if user exists
    let user = await User.findByGoogleId(uid);

    // ➕ Create user if doesn't exist
    if (!user) {
      user = await User.create({
        email,
        firstName,
        lastName,
        googleId: uid,
        avatarUrl: picture,
      });
    }

    // 🎟 Generate session token
    const token = generateToken(user);
    await storeSession(user.id, token, req.get('User-Agent'), req.ip);

    // 🧹 Remove sensitive fields
    const {
      password_hash,
      reset_token,
      reset_token_expires,
      ...userResponse
    } = user;

    res.json({
      success: true,
      message: 'Google login successful',
      token,
      user: userResponse,
    });

  } catch (err) {
    console.error('Google login error:', err);
    res.status(401).json({ success: false, message: 'Google login failed' });
  }
};



// Change password (for authenticated users)
const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    // Get user with password hash
    const user = await User.findByEmail(req.user.email);
    if (!user || !user.password_hash) {
      return res.status(400).json({
        success: false,
        message: 'Cannot change password for this account'
      });
    }

    // Verify current password
    const isCurrentPasswordValid = await User.verifyPassword(currentPassword, user.password_hash);
    if (!isCurrentPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Update password
    await User.resetPassword(userId, newPassword);

    res.json({
      success: true,
      message: 'Password changed successfully'
    });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to change password'
    });
  }
};

module.exports = {
  signup,
  login,
  adminLogin,
  logout,
  verifyToken,
  forgotPassword,
  resetPassword,
  googleLogin,
  changePassword
};
