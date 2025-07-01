import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';
import Cookies from 'js-cookie';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Create axios instance WITH /api in baseURL (your backend uses /api prefix)
  const api = axios.create({
    baseURL: `${process.env.REACT_APP_API_URL || 'http://localhost:5000'}/api`,
    timeout: 60000,
    headers: {
      'Content-Type': 'application/json',
    },
  });

  console.log('🔍 Axios baseURL set to:', api.defaults.baseURL);
  console.log('🔍 Environment variable:', process.env.REACT_APP_API_URL);

  // Request interceptor to add auth token
  api.interceptors.request.use(
    (config) => {
      const token = Cookies.get('token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
        console.log('🔑 Adding token to request:', token.substring(0, 20) + '...');
      } else {
        console.log('⚠️ No token found for request to:', config.url);
      }
      return config;
    },
    (error) => Promise.reject(error)
  );

  // Response interceptor for error handling
  api.interceptors.response.use(
    (response) => {
      console.log('✅ API Response:', response.config.url, response.status);
      return response;
    },
    (error) => {
      console.error('❌ API Error:', error.config?.url, error.response?.status, error.message);
      
      if (error.code === 'ECONNABORTED') {
        console.error('Request timeout - server may be sleeping (Render cold start)');
        setError('Server is starting up, please wait a moment and try again...');
      } else if (error.response?.status === 401) {
        console.log('Token invalid, clearing auth state');
        logout();
      } else if (!error.response) {
        console.error('Network error - server may be down');
        setError('Unable to connect to server. Please check your connection.');
      }
      return Promise.reject(error);
    }
  );

  useEffect(() => {
    let mounted = true;
    
    const initializeAuth = async () => {
      console.log('🚀 Initializing authentication...');
      const token = Cookies.get('token');
      console.log('🔍 Found token in cookies:', token ? 'Yes' : 'No');
      
      if (token && mounted) {
        console.log('🔄 Verifying existing token...');
        await verifyToken();
      } else if (mounted) {
        console.log('📭 No token found, setting loading to false');
        setLoading(false);
      }
    };

    initializeAuth();

    return () => {
      mounted = false;
    };
  }, []);

  const verifyToken = async () => {
    try {
      setError(null);
      console.log('🔍 Verifying token with backend...');
      
      const response = await api.get('/auth/verify');
      
      console.log('🔍 Token verification response:', response.data);
      
      if (response.data.success) {
        setUser(response.data.user);
        console.log('✅ Token verified successfully, user set:', response.data.user);
      } else {
        console.error('❌ Token verification failed:', response.data);
        throw new Error('Token verification failed');
      }
    } catch (error) {
      console.error('❌ Token verification error:', error);
      console.error('❌ Error response data:', error.response?.data);
      
      if (error.code === 'ECONNABORTED') {
        setError('Server is starting up, please wait...');
        // Don't logout on timeout - server might just be cold starting
      } else if (error.response?.status === 401) {
        setError('Session expired. Please log in again.');
        logout();
      } else if (!error.response) {
        setError('Unable to connect to server. Please check your connection.');
        // Don't logout on network error - might be temporary
      } else {
        setError('Authentication failed. Please try logging in again.');
        logout();
      }
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password, isAdmin = false) => {
    try {
      setError(null);
      setLoading(true);
      
      const endpoint = isAdmin ? '/auth/admin/login' : '/auth/login';
      console.log('🔍 Attempting login to:', endpoint);
      console.log('🔍 Request data:', { email, password: '***masked***' });
      
      const response = await api.post(endpoint, { email, password });
      
      console.log('🔍 Login response status:', response.status);
      console.log('🔍 Login response data:', response.data);
      
      // Handle different possible response formats
      let token, userData;
      
      if (response.data.token && response.data.user) {
        // Format: { token: "...", user: {...} }
        token = response.data.token;
        userData = response.data.user;
        console.log('✅ Found token and user in response');
      } else if (response.data.success && response.data.data) {
        // Format: { success: true, data: { token: "...", user: {...} } }
        token = response.data.data.token;
        userData = response.data.data.user;
        console.log('✅ Found token and user in response.data');
      } else if (response.data.accessToken) {
        // Format: { accessToken: "...", user: {...} }
        token = response.data.accessToken;
        userData = response.data.user;
        console.log('✅ Found accessToken and user in response');
      } else {
        console.error('❌ Unexpected response format:', response.data);
        throw new Error('Unexpected login response format');
      }
      
      console.log('🔍 Extracted token:', token ? 'Present (' + token.length + ' chars)' : 'Missing');
      console.log('🔍 Extracted user:', userData);
      
      if (token) {
        Cookies.set('token', token, { expires: 7 });
        console.log('✅ Token stored in cookies');
        
        // Verify the token was actually stored
        const storedToken = Cookies.get('token');
        console.log('✅ Token verification in cookies:', storedToken ? 'Success' : 'Failed');
      } else {
        console.error('❌ No token found in response!');
        throw new Error('No authentication token received');
      }
      
      if (userData) {
        setUser(userData);
        console.log('✅ User data set in state');
      } else {
        console.error('❌ No user data found in response!');
        throw new Error('No user data received');
      }
      
      console.log('🎉 Login successful');
      return { success: true };
      
    } catch (error) {
      console.error('❌ Login error:', error);
      console.error('❌ Error response:', error.response?.data);
      console.error('❌ Error status:', error.response?.status);
      
      let errorMessage = 'Login failed. Please try again.';
      
      if (error.code === 'ECONNABORTED') {
        errorMessage = 'Server is starting up, please wait a moment and try again...';
      } else if (error.response?.data?.message) {
        errorMessage = error.response.data.message;
      } else if (error.response?.status === 401) {
        errorMessage = 'Invalid email or password';
      } else if (error.response?.status === 400) {
        errorMessage = 'Invalid login request';
      } else if (!error.response) {
        errorMessage = 'Unable to connect to server. Please check your connection.';
      }
      
      setError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setLoading(false);
    }
  };

  const signup = async (userData) => {
    try {
      setError(null);
      setLoading(true);
      
      console.log('🔍 Attempting signup...');
      console.log('🔍 Signup data:', { ...userData, password: '***masked***' });
      
      const response = await api.post('/auth/signup', userData);
      
      console.log('🔍 Signup response:', response.data);
      
      // Handle different possible response formats (same as login)
      let token, newUser;
      
      if (response.data.token && response.data.user) {
        token = response.data.token;
        newUser = response.data.user;
      } else if (response.data.success && response.data.data) {
        token = response.data.data.token;
        newUser = response.data.data.user;
      } else if (response.data.accessToken) {
        token = response.data.accessToken;
        newUser = response.data.user;
      } else {
        console.error('❌ Unexpected signup response format:', response.data);
        // If signup doesn't return token immediately, just return success
        return { success: true, message: 'Account created successfully. Please log in.' };
      }
      
      if (token && newUser) {
        Cookies.set('token', token, { expires: 7 });
        setUser(newUser);
        console.log('✅ Signup successful with auto-login');
      }
      
      return { success: true };
      
    } catch (error) {
      console.error('❌ Signup error:', error);
      console.error('❌ Error response:', error.response?.data);
      
      let errorMessage = 'Signup failed. Please try again.';
      
      if (error.code === 'ECONNABORTED') {
        errorMessage = 'Server is starting up, please wait a moment and try again...';
      } else if (error.response?.data?.message) {
        errorMessage = error.response.data.message;
      } else if (error.response?.status === 400) {
        errorMessage = 'Invalid signup data. Please check your information.';
      } else if (error.response?.status === 409) {
        errorMessage = 'Email already exists. Please use a different email.';
      } else if (!error.response) {
        errorMessage = 'Unable to connect to server. Please check your connection.';
      }
      
      setError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    console.log('🚪 Logging out user...');
    Cookies.remove('token');
    setUser(null);
    setError(null);
    console.log('✅ User logged out, token removed');
  };

  const forgotPassword = async (email) => {
    try {
      setError(null);
      console.log('📧 Requesting password reset for:', email);
      
      await api.post('/auth/forgot-password', { email });
      console.log('✅ Password reset email sent');
      return { success: true };
      
    } catch (error) {
      console.error('❌ Forgot password error:', error);
      
      let errorMessage = 'Failed to send reset email';
      
      if (error.code === 'ECONNABORTED') {
        errorMessage = 'Server is starting up, please wait a moment and try again...';
      } else if (error.response?.data?.message) {
        errorMessage = error.response.data.message;
      } else if (!error.response) {
        errorMessage = 'Unable to connect to server. Please check your connection.';
      }
      
      setError(errorMessage);
      return { success: false, error: errorMessage };
    }
  };

  const resetPassword = async (token, password) => {
    try {
      setError(null);
      console.log('🔒 Resetting password with token...');
      
      await api.post('/auth/reset-password', { token, password });
      console.log('✅ Password reset successful');
      return { success: true };
      
    } catch (error) {
      console.error('❌ Reset password error:', error);
      
      let errorMessage = 'Failed to reset password';
      
      if (error.code === 'ECONNABORTED') {
        errorMessage = 'Server is starting up, please wait a moment and try again...';
      } else if (error.response?.data?.message) {
        errorMessage = error.response.data.message;
      } else if (!error.response) {
        errorMessage = 'Unable to connect to server. Please check your connection.';
      }
      
      setError(errorMessage);
      return { success: false, error: errorMessage };
    }
  };

  const googleLogin = async (credential) => {
    try {
      setError(null);
      setLoading(true);
      
      console.log('🔍 Attempting Google login...');
      
      const response = await api.post('/auth/google', { credential });
      
      console.log('🔍 Google login response:', response.data);
      
      // Handle response format (same as regular login)
      let token, userData;
      
      if (response.data.token && response.data.user) {
        token = response.data.token;
        userData = response.data.user;
      } else if (response.data.success && response.data.data) {
        token = response.data.data.token;
        userData = response.data.data.user;
      } else if (response.data.accessToken) {
        token = response.data.accessToken;
        userData = response.data.user;
      }
      
      if (token && userData) {
        Cookies.set('token', token, { expires: 7 });
        setUser(userData);
        console.log('✅ Google login successful');
      }
      
      return { success: true };
      
    } catch (error) {
      console.error('❌ Google login error:', error);
      
      let errorMessage = 'Google login failed';
      
      if (error.code === 'ECONNABORTED') {
        errorMessage = 'Server is starting up, please wait a moment and try again...';
      } else if (error.response?.data?.message) {
        errorMessage = error.response.data.message;
      } else if (!error.response) {
        errorMessage = 'Unable to connect to server. Please check your connection.';
      }
      
      setError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setLoading(false);
    }
  };

  const retryConnection = async () => {
    console.log('🔄 Retrying connection...');
    if (Cookies.get('token')) {
      setLoading(true);
      await verifyToken();
    } else {
      // Try to refresh the page or clear any errors
      setError(null);
      setLoading(false);
    }
  };

  const loginWithToken = async (token, userData) => {
  try {
    Cookies.set('token', token, { expires: 7 });
    setUser(userData);
    console.log('✅ loginWithToken(): Token saved, user set');
    return { success: true };
  } catch (err) {
    console.error('❌ loginWithToken error:', err);
    return { success: false, error: 'Login failed' };
  }
};


  const value = {
    user,
    loading,
    error,
    login,
    signup,
    logout,
    forgotPassword,
    resetPassword,
    googleLogin,
    loginWithToken,
    retryConnection,
    api
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
