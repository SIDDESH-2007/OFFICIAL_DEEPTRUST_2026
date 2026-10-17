/**
 * apiService.js
 * Secure API abstraction layer.
 *
 * Security design notes:
 * - Centralizes request creation and response normalization.
 * - Allows caller to pass authorization headers without exposing token internals.
 * - Intentionally avoids logging sensitive payloads.
 */

const DEFAULT_HEADERS = {
    'Content-Type': 'application/json',
    Accept: 'application/json'
};

const parseErrorMessage = async (response) => {
    try {
        const body = await response.json();
        return body?.message || `Request failed with status ${response.status}`;
    } catch {
        return `Request failed with status ${response.status}`;
    }
};

const parseJson = async (response) => {
    try {
        return await response.json();
    } catch {
        return {};
    }
};

export const postJson = async (endpoint, payload, { authHeaders = {}, signal } = {}) => {
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                ...DEFAULT_HEADERS,
                ...authHeaders
            },
            body: JSON.stringify(payload),
            signal
        });

        if (!response.ok) {
            throw new Error(await parseErrorMessage(response));
        }

        return await parseJson(response);
    } catch (error) {
        throw new Error(error?.message || 'Unable to complete request');
    }
};
