import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'sonner';
import { API } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Shield, Upload, FileText, Download, Mail, Trash2, Lock, AlertTriangle, CheckCircle, LogOut, Eye, EyeOff } from 'lucide-react';

export default function Dashboard() {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [files, setFiles] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [detectionResults, setDetectionResults] = useState(null);
  const [encryptionPassword, setEncryptionPassword] = useState('');
  const [showEncryptPassword, setShowEncryptPassword] = useState(false);
  const [decryptPassword, setDecryptPassword] = useState('');
  const [showDecryptPassword, setShowDecryptPassword] = useState(false);
  const [fileToDecrypt, setFileToDecrypt] = useState(null);
  const [showDecryptDialog, setShowDecryptDialog] = useState(false);
  const [fileToDelete, setFileToDelete] = useState(null);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);

  useEffect(() => {
    const userData = localStorage.getItem('user');
    if (userData) {
      setUser(JSON.parse(userData));
    }
    loadFiles();
  }, []);

  const loadFiles = async () => {
    try {
      const response = await axios.get(`${API}/files`);
      setFiles(response.data);
    } catch (error) {
      console.error('Failed to load files:', error);
    }
  };

  const handleFileSelect = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setIsLoading(true);
    setDetectionResults(null);
    setSelectedFile(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await axios.post(`${API}/files/analyze`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      setDetectionResults(response.data);
      setSelectedFile(file);

      if (response.data.has_sensitive_data) {
        toast.warning('Sensitive data detected! Encryption recommended.');
      } else {
        toast.success('No sensitive data detected.');
      }
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to analyze file');
    } finally {
      setIsLoading(false);
    }
  };

  const handleEncrypt = async () => {
    if (!selectedFile || !encryptionPassword) {
      toast.error('Please select a file and enter a password');
      return;
    }

    if (encryptionPassword.length < 6) {
      toast.error('Password must be at least 6 characters');
      return;
    }

    setIsLoading(true);

    try {
      // Read file as base64
      const reader = new FileReader();
      reader.onload = async (e) => {
        const base64Content = e.target.result.split(',')[1];

        const response = await axios.post(`${API}/files/encrypt`, {
          file_content: base64Content,
          filename: selectedFile.name,
          password: encryptionPassword,
          detection_results: detectionResults || {}
        });

        toast.success('File encrypted successfully!');
        setSelectedFile(null);
        setDetectionResults(null);
        setEncryptionPassword('');
        loadFiles();
      };
      reader.readAsDataURL(selectedFile);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Encryption failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDecrypt = async () => {
    if (!decryptPassword) {
      toast.error('Please enter the decryption password');
      return;
    }

    setIsLoading(true);

    try {
      const response = await axios.post(`${API}/files/${fileToDecrypt.id}/decrypt`, {
        password: decryptPassword
      });

      // Download the decrypted file
      const blob = new Blob([atob(response.data.content)], { type: 'application/octet-stream' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = response.data.filename;
      a.click();
      window.URL.revokeObjectURL(url);

      toast.success('File decrypted and downloaded!');
      setShowDecryptDialog(false);
      setDecryptPassword('');
      setFileToDecrypt(null);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Decryption failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDownloadEncrypted = (file) => {
    const blob = new Blob([atob(file.encrypted_data)], { type: 'application/octet-stream' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${file.original_filename}.encrypted`;
    a.click();
    window.URL.revokeObjectURL(url);
    toast.success('Encrypted file downloaded!');
  };

  const handleEmailFile = (file) => {
    const subject = encodeURIComponent(`Encrypted File: ${file.original_filename}`);
    const body = encodeURIComponent(
      `I'm sharing an encrypted file with you.\n\nFilename: ${file.original_filename}\nEncrypted on: ${new Date(file.created_at).toLocaleString()}\n\nPlease find the encrypted file attached. You'll need the password to decrypt it.`
    );
    window.location.href = `mailto:?subject=${subject}&body=${body}`;
  };

  const handleDeleteFile = async () => {
    if (!fileToDelete) return;

    setIsLoading(true);
    try {
      await axios.delete(`${API}/files/${fileToDelete.id}`);
      toast.success('File deleted successfully');
      loadFiles();
      setShowDeleteDialog(false);
      setFileToDelete(null);
    } catch (error) {
      toast.error('Failed to delete file');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    navigate('/auth');
    toast.success('Logged out successfully');
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };

  return (
    <div className="min-h-screen" style={{ background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)' }}>
      {/* Header */}
      <header className="glass-strong border-b border-slate-700 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>CryptoSecure</h1>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right hidden sm:block">
                <p className="text-sm text-white font-medium">{user?.name}</p>
                <p className="text-xs text-slate-400">{user?.email}</p>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={handleLogout}
                className="border-slate-700 bg-slate-800/50 text-white hover:bg-slate-700"
                data-testid="logout-button"
              >
                <LogOut className="w-4 h-4 mr-2" />
                Logout
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid lg:grid-cols-3 gap-6">
          {/* Upload & Encrypt Section */}
          <div className="lg:col-span-1 space-y-6">
            <Card className="glass-strong border-slate-700" data-testid="upload-card">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Upload className="w-5 h-5" />
                  Upload & Encrypt
                </CardTitle>
                <CardDescription className="text-slate-400">Analyze and encrypt your files</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="file-upload" className="cursor-pointer">
                    <div className="border-2 border-dashed border-slate-600 rounded-lg p-8 text-center hover:border-blue-500 hover:bg-slate-800/30 transition-all" data-testid="file-upload-zone">
                      <Upload className="w-8 h-8 mx-auto mb-2 text-slate-400" />
                      <p className="text-sm text-slate-300 font-medium">Click to upload file</p>
                      <p className="text-xs text-slate-500 mt-1">or drag and drop</p>
                    </div>
                    <Input
                      id="file-upload"
                      type="file"
                      className="hidden"
                      onChange={handleFileSelect}
                      disabled={isLoading}
                      data-testid="file-upload-input"
                    />
                  </Label>
                </div>

                {detectionResults && (
                  <div className="space-y-3 animate-fadeIn">
                    <div className={`p-4 rounded-lg border ${
                      detectionResults.has_sensitive_data
                        ? 'bg-orange-500/10 border-orange-500/30'
                        : 'bg-green-500/10 border-green-500/30'
                    }`} data-testid="detection-results">
                      <div className="flex items-start gap-3">
                        {detectionResults.has_sensitive_data ? (
                          <AlertTriangle className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
                        ) : (
                          <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                        )}
                        <div className="flex-1">
                          <h4 className="font-medium text-white text-sm mb-1">
                            {detectionResults.has_sensitive_data
                              ? 'Sensitive Data Detected'
                              : 'No Sensitive Data Found'}
                          </h4>
                          {detectionResults.detected_patterns.length > 0 && (
                            <div className="space-y-2 mt-2">
                              {detectionResults.detected_patterns.map((pattern, idx) => (
                                <div key={idx} className="text-xs">
                                  <span className="text-slate-300 font-medium">{pattern.type}:</span>
                                  <span className="text-slate-400 ml-1">{pattern.count} found</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>

                    {detectionResults.has_sensitive_data && (
                      <div className="space-y-3">
                        <div className="space-y-2">
                          <Label htmlFor="encrypt-password" className="text-slate-200">Encryption Password</Label>
                          <div className="relative">
                            <Input
                              id="encrypt-password"
                              type={showEncryptPassword ? 'text' : 'password'}
                              placeholder="Enter strong password"
                              value={encryptionPassword}
                              onChange={(e) => setEncryptionPassword(e.target.value)}
                              className="bg-slate-800/50 border-slate-700 text-white pr-10"
                              data-testid="encryption-password-input"
                            />
                            <button
                              type="button"
                              onClick={() => setShowEncryptPassword(!showEncryptPassword)}
                              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                            >
                              {showEncryptPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                          </div>
                          <p className="text-xs text-slate-400">Minimum 6 characters</p>
                        </div>
                        <Button
                          onClick={handleEncrypt}
                          disabled={isLoading || !encryptionPassword}
                          className="w-full bg-blue-600 hover:bg-blue-700"
                          data-testid="encrypt-button"
                        >
                          <Lock className="w-4 h-4 mr-2" />
                          {isLoading ? 'Encrypting...' : 'Encrypt File'}
                        </Button>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Files List Section */}
          <div className="lg:col-span-2">
            <Card className="glass-strong border-slate-700" data-testid="files-list-card">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <FileText className="w-5 h-5" />
                  Encrypted Files
                </CardTitle>
                <CardDescription className="text-slate-400">
                  {files.length} encrypted {files.length === 1 ? 'file' : 'files'}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {files.length === 0 ? (
                  <div className="text-center py-12">
                    <Lock className="w-12 h-12 mx-auto mb-3 text-slate-600" />
                    <p className="text-slate-400">No encrypted files yet</p>
                    <p className="text-sm text-slate-500 mt-1">Upload and encrypt your first file to get started</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {files.map((file) => (
                      <div
                        key={file.id}
                        className="p-4 rounded-lg bg-slate-800/40 border border-slate-700 hover:bg-slate-800/60 hover:border-slate-600 transition-all card-hover"
                        data-testid={`file-item-${file.id}`}
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1 min-w-0">
                            <h4 className="font-medium text-white truncate" data-testid="file-name">{file.original_filename}</h4>
                            <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-xs text-slate-400">
                              <span>Size: {formatFileSize(file.file_size)}</span>
                              <span>Encrypted: {new Date(file.created_at).toLocaleDateString()}</span>
                              {file.detection_results?.has_sensitive_data && (
                                <span className="text-orange-400" data-testid="sensitive-data-badge">
                                  Contains sensitive data
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="flex gap-2 flex-shrink-0">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => {
                                setFileToDecrypt(file);
                                setShowDecryptDialog(true);
                              }}
                              className="border-slate-700 bg-slate-800/50 hover:bg-blue-600 hover:border-blue-600 text-white"
                              data-testid="decrypt-file-button"
                            >
                              <Download className="w-4 h-4" />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleEmailFile(file)}
                              className="border-slate-700 bg-slate-800/50 hover:bg-green-600 hover:border-green-600 text-white"
                              data-testid="email-file-button"
                            >
                              <Mail className="w-4 h-4" />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => {
                                setFileToDelete(file);
                                setShowDeleteDialog(true);
                              }}
                              className="border-slate-700 bg-slate-800/50 hover:bg-red-600 hover:border-red-600 text-white"
                              data-testid="delete-file-button"
                            >
                              <Trash2 className="w-4 h-4" />
                            </Button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </main>

      {/* Decrypt Dialog */}
      <AlertDialog open={showDecryptDialog} onOpenChange={setShowDecryptDialog}>
        <AlertDialogContent className="glass-strong border-slate-700" data-testid="decrypt-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-white">Decrypt File</AlertDialogTitle>
            <AlertDialogDescription className="text-slate-400">
              Enter the password to decrypt <span className="font-medium text-white">{fileToDecrypt?.original_filename}</span>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-2 py-4">
            <Label htmlFor="decrypt-password" className="text-slate-200">Password</Label>
            <div className="relative">
              <Input
                id="decrypt-password"
                type={showDecryptPassword ? 'text' : 'password'}
                placeholder="Enter decryption password"
                value={decryptPassword}
                onChange={(e) => setDecryptPassword(e.target.value)}
                className="bg-slate-800/50 border-slate-700 text-white pr-10"
                data-testid="decrypt-password-input"
                onKeyDown={(e) => e.key === 'Enter' && handleDecrypt()}
              />
              <button
                type="button"
                onClick={() => setShowDecryptPassword(!showDecryptPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
              >
                {showDecryptPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel className="border-slate-700 bg-slate-800/50 text-white hover:bg-slate-700" data-testid="decrypt-cancel-button">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDecrypt}
              disabled={isLoading || !decryptPassword}
              className="bg-blue-600 hover:bg-blue-700"
              data-testid="decrypt-confirm-button"
            >
              {isLoading ? 'Decrypting...' : 'Decrypt & Download'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent className="glass-strong border-slate-700" data-testid="delete-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-white">Delete File</AlertDialogTitle>
            <AlertDialogDescription className="text-slate-400">
              Are you sure you want to delete <span className="font-medium text-white">{fileToDelete?.original_filename}</span>? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="border-slate-700 bg-slate-800/50 text-white hover:bg-slate-700" data-testid="delete-cancel-button">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteFile}
              disabled={isLoading}
              className="bg-red-600 hover:bg-red-700"
              data-testid="delete-confirm-button"
            >
              {isLoading ? 'Deleting...' : 'Delete'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}