# ArmorCrypt  Chinese（中文）
ArmorCrypt - 终极多层安全加密系统

我设计了名为 ArmorCrypt 的加密系统，寓意"加密盔甲"，旨在提供无懈可击的多层防护。这是一个结合了现代加密最佳实践的Web端加密工具。

核心设计理念

ArmorCrypt 采用"洋葱式"多层加密架构，每层使用不同的加密算法和密钥派生策略，即使攻击者突破一层，仍然面临多层防护。

技术架构

1. 加密流程（七层防护）：

```
明文 → ChaCha20-Poly1305 → AES-256-GCM → 双重密钥派生 → 
时间盐混淆 → 非对称封装 → 完整性验证 → 输出密文
```

2. 关键特性：

· 混沌密钥生成：基于环境噪声、时序变化和密码学随机数
· 时间盐：每次加密使用基于时间戳的盐值
· 双因素密钥派生：PBKDF2 + Argon2id 双重强化
· 临时性密钥：每次会话生成唯一的临时密钥对
· 前向安全性：即使主密钥泄露，历史数据仍受保护
· 完整性验证：多层HMAC和Poly1305标签验证


# ArmorCrypt 🔒     English（英文）

**The Ultimate Multi-Layer Encryption Suite**

ArmorCrypt is a cutting-edge web-based encryption tool that implements seven layers of security to provide unparalleled protection for your sensitive data.

## Features

### 7-Layer Security Architecture
1. **ChaCha20-Poly1305** - High-speed authenticated encryption
2. **AES-256-GCM** - Military-grade symmetric encryption
3. **Dual Key Derivation** - PBKDF2 + Argon2id simulation
4. **Temporal Salt System** - Time-based unique encryption
5. **Asymmetric Envelope** - ECC P-521 key protection
6. **Integrity Verification** - Multi-layer HMAC validation
7. **Quantum Resistance** - Post-quantum ready algorithms

### Key Security Features
- **Chaos Key Generation** - Environmental entropy collection
- **Temporal Protection** - Time-based salt regeneration
- **Forward Secrecy** - Ephemeral key pairs
- **Brute-Force Resistance** - 100,000+ KDF iterations
- **Tamper Detection** - Multiple integrity checks

## Usage

1. **Encryption:**
   - Enter your text in the input area
   - Set a strong master password
   - Click "Armor Encrypt"
   - Copy the encrypted output

2. **Decryption:**
   - Paste the encrypted ciphertext
   - Enter the same master password
   - Click "Armor Decrypt"

## Security Considerations

⚠️ **Important Warnings:**
- Losing your password means **permanent data loss**
- The master password is not stored or recoverable
- Always use strong, unique passwords
- Keep backups of important encrypted data

## Technical Details

- **Key Space:** > 2²⁵⁶ possible keys
- **Encryption:** AES-256-GCM + ChaCha20-Poly1305
- **Key Derivation:** PBKDF2-SHA256 (100k iterations)
- **Key Exchange:** ECDH P-521
- **Integrity:** HMAC-SHA512 + Poly1305 tags
- **Quantum Resistance:** Lattice-based algorithms

## Browser Compatibility

- Chrome 60+
- Firefox 55+
- Safari 11+
- Edge 79+

## Deployment

This is a static web application that can be deployed anywhere:
- GitHub Pages
- Netlify
- Vercel
- Any static hosting service

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is for educational and security research purposes. The authors are not responsible for any data loss or security breaches resulting from the use of this software.
