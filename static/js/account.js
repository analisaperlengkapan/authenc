// Account Console JavaScript
class AccountConsole {
    constructor() {
        this.apiBase = '/api/v1';
        this.currentUser = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadUserProfile();
        this.loadInitialData();
    }

    setupEventListeners() {
        // Tab navigation
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });

        // Profile form
        document.getElementById('profile-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.updateProfile();
        });

        // Password form
        document.getElementById('password-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.changePassword();
        });

        // 2FA buttons
        document.getElementById('setup-tfa-btn').addEventListener('click', () => this.setupTFA());
        document.getElementById('disable-tfa-btn').addEventListener('click', () => this.disableTFA());

        // Privacy buttons
        document.getElementById('export-data-btn').addEventListener('click', () => this.exportData());
        document.getElementById('delete-account-btn').addEventListener('click', () => this.confirmDeleteAccount());

        // Logout button
        document.getElementById('logout-btn').addEventListener('click', () => this.logout());

        // Modal
        document.querySelector('.modal-close').addEventListener('click', () => this.closeModal());
        document.getElementById('modal-cancel').addEventListener('click', () => this.closeModal());
        document.getElementById('modal-confirm').addEventListener('click', () => this.executeModalAction());
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${tabName}-tab`).classList.add('active');

        // Load tab-specific data
        switch(tabName) {
            case 'sessions':
                this.loadSessions();
                break;
            case 'applications':
                this.loadApplications();
                break;
            case 'security':
                this.loadTFASettings();
                break;
        }
    }

    async loadUserProfile() {
        try {
            const response = await this.apiCall('/account');
            this.currentUser = response;
            this.populateProfileForm(response);
            document.getElementById('user-email').textContent = response.email;
        } catch (error) {
            this.showError('Failed to load user profile');
            console.error('Profile load error:', error);
        }
    }

    populateProfileForm(user) {
        document.getElementById('firstName').value = user.first_name || '';
        document.getElementById('lastName').value = user.last_name || '';
        document.getElementById('email').value = user.email || '';
        document.getElementById('username').value = user.username || '';
    }

    async updateProfile() {
        const formData = {
            first_name: document.getElementById('firstName').value,
            last_name: document.getElementById('lastName').value,
            username: document.getElementById('username').value
        };

        try {
            await this.apiCall('/account', 'PUT', formData);
            this.showSuccess('Profile updated successfully');
            this.loadUserProfile(); // Refresh data
        } catch (error) {
            this.showError('Failed to update profile');
            console.error('Profile update error:', error);
        }
    }

    async changePassword() {
        const currentPassword = document.getElementById('currentPassword').value;
        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (newPassword !== confirmPassword) {
            this.showError('New passwords do not match');
            return;
        }

        try {
            await this.apiCall('/account/credentials/password', 'PUT', {
                current_password: currentPassword,
                new_password: newPassword
            });
            this.showSuccess('Password changed successfully');
            document.getElementById('password-form').reset();
        } catch (error) {
            this.showError('Failed to change password');
            console.error('Password change error:', error);
        }
    }

    async loadSessions() {
        try {
            const sessions = await this.apiCall('/account/sessions');
            this.renderSessions(sessions);
        } catch (error) {
            this.showError('Failed to load sessions');
            console.error('Sessions load error:', error);
        }
    }

    renderSessions(sessions) {
        const container = document.getElementById('sessions-list');

        if (sessions.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-desktop"></i>
                    <p>No active sessions found</p>
                </div>
            `;
            return;
        }

        container.innerHTML = sessions.map(session => `
            <div class="session-item">
                <div class="session-info">
                    <h4>${session.client_name || 'Unknown Client'}</h4>
                    <p>Started: ${new Date(session.created_at).toLocaleString()}</p>
                    <p>IP: ${session.ip_address || 'Unknown'}</p>
                </div>
                <div class="session-actions">
                    <button class="btn-danger btn-small" onclick="accountConsole.revokeSession('${session.id}')">
                        <i class="fas fa-times"></i> Revoke
                    </button>
                </div>
            </div>
        `).join('');
    }

    async revokeSession(sessionId) {
        try {
            await this.apiCall(`/account/sessions/${sessionId}`, 'DELETE');
            this.showSuccess('Session revoked successfully');
            this.loadSessions(); // Refresh list
        } catch (error) {
            this.showError('Failed to revoke session');
            console.error('Session revoke error:', error);
        }
    }

    async loadApplications() {
        try {
            const response = await this.apiCall('/auth/account/applications');
            const applications = response;

            const container = document.getElementById('applications-list');

            if (applications.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-apps"></i>
                        <p>No authorized applications found</p>
                        <p>Applications you authorize will appear here</p>
                    </div>
                `;
                return;
            }

            const html = applications.map(app => `
                <div class="application-item">
                    <div class="application-info">
                        <h4>${this.escapeHtml(app.name)}</h4>
                        <p>Client ID: ${this.escapeHtml(app.client_id)}</p>
                        <p>Authorized: ${new Date(app.created_at).toLocaleDateString()}</p>
                        ${app.last_access ? `<p>Last access: ${new Date(app.last_access).toLocaleDateString()}</p>` : ''}
                    </div>
                    <div class="application-actions">
                        <button class="btn-danger btn-small" onclick="accountConsole.revokeApplication('${app.client_id}')">
                            <i class="fas fa-times"></i> Revoke Access
                        </button>
                    </div>
                </div>
            `).join('');

            container.innerHTML = html;
        } catch (error) {
            console.error('Failed to load applications:', error);
            document.getElementById('applications-list').innerHTML = `
                <div class="error-state">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>Failed to load applications</p>
                </div>
            `;
        }
    }

    async revokeApplication(clientId) {
        if (!confirm(`Are you sure you want to revoke access for application ${clientId}?`)) {
            return;
        }

        try {
            await this.apiCall(`/auth/account/applications/${clientId}`, 'DELETE');
            this.showSuccess('Application access revoked successfully');
            this.loadApplications(); // Refresh the list
        } catch (error) {
            this.showError('Failed to revoke application access');
            console.error('Revoke application error:', error);
        }
    }

    async loadTFASettings() {
        // For now, show 2FA as not configured
        const container = document.getElementById('tfa-status');
        container.innerHTML = `
            <p><i class="fas fa-times-circle" style="color: var(--danger-color);"></i> Two-factor authentication is not configured</p>
        `;
        document.getElementById('setup-tfa-btn').style.display = 'inline-block';
        document.getElementById('disable-tfa-btn').style.display = 'none';
    }

    async setupTFA() {
        try {
            // Step 1: Setup TOTP - get secret and QR code
            const response = await fetch(`${this.apiBase}/auth/account/credentials/totp/setup`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.getAuthToken()}`
                },
                body: JSON.stringify({
                    user_label: this.currentUser?.username || 'User'
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || 'Failed to setup TOTP');
            }

            const setupData = await response.json();
            
            // Show QR code modal
            this.showQRCodeModal(setupData.secret, setupData.qr_code_uri, setupData.user_label);
            
        } catch (error) {
            this.showError('Failed to setup 2FA: ' + error.message);
            console.error('TOTP setup error:', error);
        }
    }

    showQRCodeModal(secret, qrCodeUri, userLabel) {
        const modal = document.getElementById('modal');
        const modalContent = modal.querySelector('.modal-content');
        
        modalContent.innerHTML = `
            <div class="modal-header">
                <h3>Setup Two-Factor Authentication</h3>
                <span class="modal-close">&times;</span>
            </div>
            <div class="modal-body">
                <p>Scan this QR code with your authenticator app:</p>
                <div class="qr-code-container">
                    <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(qrCodeUri)}" 
                         alt="TOTP QR Code" class="qr-code">
                </div>
                <p class="manual-secret">
                    Or enter this code manually: <code>${secret}</code>
                </p>
                <div class="form-group">
                    <label for="totp-code">Enter the 6-digit code from your app:</label>
                    <input type="text" id="totp-code" maxlength="6" pattern="[0-9]{6}" required>
                </div>
            </div>
            <div class="modal-footer">
                <button id="modal-cancel" class="btn btn-secondary">Cancel</button>
                <button id="modal-confirm" class="btn btn-primary">Verify & Enable</button>
            </div>
        `;
        
        modal.style.display = 'block';
        
        // Setup event listeners
        modal.querySelector('.modal-close').addEventListener('click', () => this.closeModal());
        document.getElementById('modal-cancel').addEventListener('click', () => this.closeModal());
        document.getElementById('modal-confirm').addEventListener('click', () => {
            const code = document.getElementById('totp-code').value;
            if (code.length === 6 && /^\d{6}$/.test(code)) {
                this.verifyTOTPSetup(code);
            } else {
                this.showError('Please enter a valid 6-digit code');
            }
        });
    }

    async verifyTOTPSetup(code) {
        try {
            const response = await fetch(`${this.apiBase}/auth/account/credentials/totp/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.getAuthToken()}`
                },
                body: JSON.stringify({ code })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || 'Failed to verify TOTP code');
            }

            this.closeModal();
            this.showSuccess('Two-factor authentication has been enabled!');
            this.loadCredentials(); // Refresh the credentials list
            
        } catch (error) {
            this.showError('Failed to verify TOTP code: ' + error.message);
            console.error('TOTP verification error:', error);
        }
    }

    async disableTFA() {
        if (!confirm('Are you sure you want to disable two-factor authentication? This will make your account less secure.')) {
            return;
        }

        try {
            const response = await fetch(`${this.apiBase}/auth/account/credentials/totp/disable`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${this.getAuthToken()}`
                }
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || 'Failed to disable TOTP');
            }

            this.showSuccess('Two-factor authentication has been disabled');
            this.loadCredentials(); // Refresh the credentials list
            
        } catch (error) {
            this.showError('Failed to disable 2FA: ' + error.message);
            console.error('TOTP disable error:', error);
        }
    }

    async exportData() {
        try {
            // Trigger download of account data
            const response = await fetch(`${this.apiBase}/auth/account/export`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${this.getAuthToken()}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to export data');
            }

            // Create download link
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'account-data.json';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

            this.showSuccess('Account data exported successfully');
        } catch (error) {
            this.showError('Failed to export account data');
            console.error('Data export error:', error);
        }
    }

    confirmDeleteAccount() {
        this.showModal(
            'Delete Account',
            'Are you sure you want to delete your account? This action cannot be undone and all your data will be permanently removed.',
            () => this.deleteAccount()
        );
    }

    async deleteAccount() {
        try {
            await this.apiCall('/auth/account', 'DELETE');
            this.showSuccess('Account deleted successfully');
            setTimeout(() => {
                this.logout();
            }, 2000);
        } catch (error) {
            this.showError('Failed to delete account');
            console.error('Account deletion error:', error);
        }
    }

    logout() {
        // Clear any stored tokens and redirect to logout
        localStorage.removeItem('auth_token');
        window.location.href = '/logout';
    }

    loadInitialData() {
        // Load data for the default active tab (profile)
        this.loadUserProfile();
    }

    async apiCall(endpoint, method = 'GET', data = null) {
        const config = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.getAuthToken()}`
            }
        };

        if (data) {
            config.body = JSON.stringify(data);
        }

        const response = await fetch(`${this.apiBase}${endpoint}`, config);

        if (!response.ok) {
            throw new Error(`API call failed: ${response.status} ${response.statusText}`);
        }

        return response.json();
    }

    getAuthToken() {
        // Get token from localStorage, cookie, or wherever it's stored
        return localStorage.getItem('auth_token') || this.getCookie('auth_token') || '';
    }

    getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return '';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showModal(title, message, confirmCallback) {
        document.getElementById('modal-title').textContent = title;
        document.getElementById('modal-message').textContent = message;
        this.modalConfirmCallback = confirmCallback;
        document.getElementById('modal').style.display = 'block';
    }

    closeModal() {
        document.getElementById('modal').style.display = 'none';
        this.modalConfirmCallback = null;
    }

    executeModalAction() {
        if (this.modalConfirmCallback) {
            this.modalConfirmCallback();
        }
        this.closeModal();
    }

    showSuccess(message) {
        this.showNotification(message, 'success');
    }

    showError(message) {
        this.showNotification(message, 'error');
    }

    showNotification(message, type) {
        // Simple notification - in a real app, you'd use a proper notification library
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 16px 20px;
            border-radius: 6px;
            color: white;
            font-weight: 500;
            z-index: 1001;
            animation: slideIn 0.3s ease-out;
        `;

        if (type === 'success') {
            notification.style.backgroundColor = 'var(--success-color)';
        } else {
            notification.style.backgroundColor = 'var(--danger-color)';
        }

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }
}

// Add notification animations to CSS dynamically
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// Initialize the account console when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.accountConsole = new AccountConsole();
});
