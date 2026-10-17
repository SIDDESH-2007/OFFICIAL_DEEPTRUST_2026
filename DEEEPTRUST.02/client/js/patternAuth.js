/**
 * patternAuth.js
 * Stage 2 - Pattern/password security module.
 *
 * Security design notes:
 * - Validates minimum entropy indicators client-side.
 * - Uses SHA-256 hashing to prevent plaintext transport.
 * - Salts hash with username to reduce cross-account replay utility.
 */

const encoder = new TextEncoder();

const toHex = (buffer) =>
    Array.from(new Uint8Array(buffer))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');

export const validatePatternInput = (rawPattern) => {
    if (!rawPattern || rawPattern.length < 8) {
        return { valid: false, message: 'Pattern/password must be at least 8 characters' };
    }

    const hasLetter = /[a-z]/i.test(rawPattern);
    const hasNumber = /\d/.test(rawPattern);
    if (!hasLetter || !hasNumber) {
        return { valid: false, message: 'Pattern/password must include letters and numbers' };
    }

    return { valid: true };
};

export const hashPattern = async ({ username, rawPattern }) => {
    try {
        const normalized = `${username || 'admin'}::${rawPattern}`;
        const digest = await crypto.subtle.digest('SHA-256', encoder.encode(normalized));
        return toHex(digest);
    } catch {
        throw new Error('Pattern hashing failed');
    }
};

export const clearPatternField = (fieldId = 'pattern') => {
    const patternField = document.getElementById(fieldId);
    if (patternField) {
        patternField.value = '';
    }
};
