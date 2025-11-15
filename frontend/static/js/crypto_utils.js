/**
 * Client-Side Encryption Utilities (Web Crypto API)
 * ===================================================
 * Mục đích: Mã hóa metadata nhạy cảm (cardholder name, device fingerprint)
 * trước khi gửi về backend, ngay cả khi đã có HTTPS.
 * 
 * Defense-in-depth strategy:
 *   HTTPS (TLS) → bảo vệ transport
 *   + E2E encryption → bảo vệ ngay cả khi TLS bị compromise (rare)
 * 
 * Algorithm: AES-256-GCM (AEAD)
 * Public key: Backend cung cấp ephemeral public key qua /api/get_encryption_key
 */

class PaymentCryptoUtils {
    constructor() {
        this.publicKey = null; // Sẽ fetch từ backend
    }

    /**
     * Fetch ephemeral public key từ backend
     * Backend sẽ tạo key pair mới mỗi session (hoặc rotate định kỳ)
     */
    async fetchPublicKey() {
        try {
            const response = await fetch('/api/get_encryption_key');
            const data = await response.json();
            // Import JWK public key
            this.publicKey = await crypto.subtle.importKey(
                'jwk',
                data.public_key,
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                false,
                ['encrypt']
            );
        } catch (err) {
            console.error('Failed to fetch encryption key:', err);
            throw new Error('Cannot initialize encryption');
        }
    }

    /**
     * Mã hóa plaintext bằng AES-256-GCM (symmetric) + RSA-OAEP (hybrid)
     * Hybrid encryption:
     *   1. Tạo AES key ngẫu nhiên (256-bit)
     *   2. Mã hóa plaintext bằng AES-GCM
     *   3. Mã hóa AES key bằng RSA public key
     *   4. Trả về: {encryptedData, encryptedKey, iv}
     */
    async encryptMetadata(plaintext) {
        if (!this.publicKey) {
            await this.fetchPublicKey();
        }

        // 1. Generate random AES-256 key
        const aesKey = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true, // extractable
            ['encrypt']
        );

        // 2. Generate random IV (12 bytes recommended for GCM)
        const iv = crypto.getRandomValues(new Uint8Array(12));

        // 3. Encrypt plaintext with AES-GCM
        const encoder = new TextEncoder();
        const encryptedData = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            aesKey,
            encoder.encode(plaintext)
        );

        // 4. Export AES key and encrypt with RSA public key
        const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);
        const encryptedKey = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            this.publicKey,
            rawAesKey
        );

        // 5. Return base64-encoded components
        return {
            encryptedData: this._arrayBufferToBase64(encryptedData),
            encryptedKey: this._arrayBufferToBase64(encryptedKey),
            iv: this._arrayBufferToBase64(iv)
        };
    }

    /**
     * Utility: Convert ArrayBuffer to Base64
     */
    _arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Generate secure nonce (UUID v4)
     */
    generateNonce() {
        return crypto.randomUUID();
    }

    /**
     * Generate device fingerprint (simple version)
     * Production: use FingerprintJS or similar library
     */
    generateDeviceFingerprint() {
        const components = [
            navigator.userAgent,
            navigator.language,
            screen.colorDepth,
            screen.width + 'x' + screen.height,
            new Date().getTimezoneOffset()
        ];
        return btoa(components.join('|'));
    }
}

// Export singleton instance
window.PaymentCrypto = new PaymentCryptoUtils();
