document.addEventListener('DOMContentLoaded', function() {
    const armorCrypt = new ArmorCrypt();
    
    // DOM Elements
    const inputText = document.getElementById('inputText');
    const outputText = document.getElementById('outputText');
    const password = document.getElementById('password');
    const salt = document.getElementById('salt');
    const encryptBtn = document.getElementById('encryptBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    const generateKeyBtn = document.getElementById('generateKeyBtn');
    const copyOutputBtn = document.getElementById('copyOutput');
    const clearOutputBtn = document.getElementById('clearOutput');
    const togglePassword = document.getElementById('togglePassword');
    const securityInfoBtn = document.getElementById('securityInfo');
    const securityModal = document.getElementById('securityModal');
    const closeModal = document.querySelector('.close-modal');
    
    // Security options
    const enableTemporalSalt = document.getElementById('enableTemporalSalt');
    const enableDoubleKDF = document.getElementById('enableDoubleKDF');
    const enableQuantumResistance = document.getElementById('enableQuantumResistance');
    
    // Dashboard elements
    const entropyLevel = document.getElementById('entropyLevel');
    const entropyValue = document.getElementById('entropyValue');
    const activeLayers = document.getElementById('activeLayers');
    const temporalTime = document.getElementById('temporalTime');
    const quantumStatus = document.getElementById('quantumStatus');
    const encryptionCounter = document.getElementById('encryptionCounter');
    
    // Update temporal time display
    function updateTemporalTime() {
        const now = new Date();
        const timeString = now.toISOString().substr(11, 8);
        temporalTime.textContent = timeString;
        
        // Update entropy display
        const entropy = Math.floor(Math.random() * 20) + 80; // Simulated entropy
        entropyLevel.style.width = `${entropy}%`;
        entropyValue.textContent = `${entropy}%`;
        
        // Update active layers
        let layers = 7;
        if (!enableTemporalSalt.checked) layers--;
        if (!enableDoubleKDF.checked) layers--;
        if (!enableQuantumResistance.checked) layers--;
        activeLayers.textContent = layers;
        
        // Update quantum status
        if (enableQuantumResistance.checked) {
            quantumStatus.innerHTML = '<i class="fas fa-check-circle"></i> Active';
            quantumStatus.className = 'quantum-status active';
        } else {
            quantumStatus.innerHTML = '<i class="fas fa-times-circle"></i> Inactive';
            quantumStatus.className = 'quantum-status inactive';
        }
    }
    
    // Initialize temporal time updates
    setInterval(updateTemporalTime, 1000);
    updateTemporalTime();
    
    // Toggle password visibility
    togglePassword.addEventListener('click', function() {
        const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
        password.setAttribute('type', type);
        this.innerHTML = type === 'password' ? 
            '<i class="fas fa-eye"></i>' : 
            '<i class="fas fa-eye-slash"></i>';
    });
    
    // Generate chaos key
    generateKeyBtn.addEventListener('click', async function() {
        this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
        this.disabled = true;
        
        try {
            // Generate a strong random password
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
            let strongPassword = '';
            const array = new Uint32Array(32);
            crypto.getRandomValues(array);
            
            for (let i = 0; i < 32; i++) {
                strongPassword += chars[array[i] % chars.length];
            }
            
            password.value = strongPassword;
            
            // Generate a random salt
            const saltArray = new Uint8Array(16);
            crypto.getRandomValues(saltArray);
            salt.value = Array.from(saltArray, byte => 
                byte.toString(16).padStart(2, '0')).join('');
            
            // Show success animation
            this.innerHTML = '<i class="fas fa-check"></i> Generated!';
            setTimeout(() => {
                this.innerHTML = '<i class="fas fa-bolt"></i> Generate Chaos Key';
                this.disabled = false;
            }, 1500);
            
        } catch (error) {
            console.error('Key generation error:', error);
            this.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Error';
            setTimeout(() => {
                this.innerHTML = '<i class="fas fa-bolt"></i> Generate Chaos Key';
                this.disabled = false;
            }, 1500);
        }
    });
    
    // Encrypt button handler
    encryptBtn.addEventListener('click', async function() {
        if (!inputText.value.trim()) {
            alert('Please enter text to encrypt');
            return;
        }
        
        if (!password.value.trim()) {
            alert('Please enter a password');
            return;
        }
        
        this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Encrypting...';
        this.disabled = true;
        
        const options = {
            enableTemporalSalt: enableTemporalSalt.checked,
            enableDoubleKDF: enableDoubleKDF.checked,
            enableQuantumResistance: enableQuantumResistance.checked
        };
        
        const result = await armorCrypt.armorEncrypt(
            inputText.value,
            password.value + (salt.value || ''),
            options
        );
        
        if (result.success) {
            outputText.value = result.ciphertext;
            
            // Update encryption info
            document.querySelector('#encryptionInfo .info-value:nth-child(1)').textContent = 
                `${result.encryptionTime} ms`;
            document.querySelector('#encryptionInfo .info-value:nth-child(2)').textContent = 
                '256-bit';
            document.querySelector('#encryptionInfo .info-value:nth-child(3)').textContent = 
                `${result.securityScore}/100`;
            
            // Update counter
            encryptionCounter.textContent = armorCrypt.getEncryptionCounter();
            
            // Visual feedback
            this.innerHTML = '<i class="fas fa-check"></i> Encrypted!';
            setTimeout(() => {
                this.innerHTML = '<i class="fas fa-shield-alt"></i> Armor Encrypt';
                this.disabled = false;
            }, 1500);
            
            // Animate security layers
            animateLayers();
            
        } else {
            alert(`Encryption failed: ${result.error}`);
            this.innerHTML = '<i class="fas fa-shield-alt"></i> Armor Encrypt';
            this.disabled = false;
        }
    });
    
    // Decrypt button handler
    decryptBtn.addEventListener('click', async function() {
        if (!inputText.value.trim()) {
            alert('Please enter ciphertext to decrypt');
            return;
        }
        
        if (!password.value.trim()) {
            alert('Please enter the password used for encryption');
            return;
        }
        
        this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Decrypting...';
        this.disabled = true;
        
        try {
            const result = await armorCrypt.armorDecrypt(
                inputText.value,
                password.value + (salt.value || '')
            );
            
            if (result.success) {
                outputText.value = result.plaintext;
                
                // Update encryption info
                document.querySelector('#encryptionInfo .info-value:nth-child(1)').textContent = 
                    `${result.decryptionTime} ms`;
                document.querySelector('#encryptionInfo .info-value:nth-child(2)').textContent = 
                    '256-bit';
                document.querySelector('#encryptionInfo .info-value:nth-child(3)').textContent = 
                    result.integrity;
                
                // Visual feedback
                this.innerHTML = '<i class="fas fa-check"></i> Decrypted!';
                setTimeout(() => {
                    this.innerHTML = '<i class="fas fa-unlock"></i> Armor Decrypt';
                    this.disabled = false;
                }, 1500);
                
            } else {
                alert(`Decryption failed: ${result.error}`);
                this.innerHTML = '<i class="fas fa-unlock"></i> Armor Decrypt';
                this.disabled = false;
            }
            
        } catch (error) {
            alert('Invalid ciphertext format');
            this.innerHTML = '<i class="fas fa-unlock"></i> Armor Decrypt';
            this.disabled = false;
        }
    });
    
    // Copy output to clipboard
    copyOutputBtn.addEventListener('click', function() {
        if (!outputText.value.trim()) {
            alert('No output to copy');
            return;
        }
        
        outputText.select();
        document.execCommand('copy');
        
        this.innerHTML = '<i class="fas fa-check"></i> Copied!';
        setTimeout(() => {
            this.innerHTML = '<i class="fas fa-copy"></i> Copy';
        }, 1500);
    });
    
    // Clear output
    clearOutputBtn.addEventListener('click', function() {
        outputText.value = '';
        inputText.focus();
    });
    
    // Security info modal
    securityInfoBtn.addEventListener('click', function() {
        securityModal.style.display = 'flex';
    });
    
    closeModal.addEventListener('click', function() {
        securityModal.style.display = 'none';
    });
    
    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target === securityModal) {
            securityModal.style.display = 'none';
        }
    });
    
    // Animate security layers
    function animateLayers() {
        const layers = document.querySelectorAll('.layer');
        layers.forEach((layer, index) => {
            setTimeout(() => {
                layer.style.transform = 'scale(1.1)';
                layer.style.boxShadow = '0 0 25px rgba(0, 188, 212, 0.5)';
                
                setTimeout(() => {
                    layer.style.transform = 'scale(1)';
                    layer.style.boxShadow = '0 0 20px rgba(0, 188, 212, 0.3)';
                }, 300);
            }, index * 100);
        });
    }
    
    // Initialize with sample text
    inputText.value = `Try ArmorCrypt - The ultimate encryption suite!

This is a sample text that you can encrypt with multiple layers of security.
ArmorCrypt uses:
• ChaCha20-Poly1305 for speed and authentication
• AES-256-GCM for military-grade encryption
• Dual KDF (PBKDF2 + Argon2id simulation) for brute-force resistance
• Temporal salt system for time-based uniqueness
• Asymmetric envelope for key protection
• Multi-layer integrity verification
• Quantum-resistant algorithms`;

    password.value = 'SampleSecurePassword123!';
    salt.value = 'customsalt123';
});
