/**
 * config/db.config.js
 * MongoDB database connection, health ping, and initial identity seeding
 */

const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/';
const MONGODB_DATABASE = process.env.MONGODB_DATABASE || 'deeptrust';

let client = null;
let db = null;
let isConnected = false;
let connectionError = null;

async function connectDB() {
    try {
        if (client && isConnected) {
            return { connected: true, db, dbName: MONGODB_DATABASE };
        }

        client = new MongoClient(MONGODB_URI, {
            serverSelectionTimeoutMS: 3000
        });

        await client.connect();
        db = client.db(MONGODB_DATABASE);

        // Actual MongoDB ping check
        await db.command({ ping: 1 });

        isConnected = true;
        connectionError = null;

        console.log(`[MongoDB] Connected successfully to database "${MONGODB_DATABASE}"`);

        // Seed initial identities in background if demo seeding is explicitly requested
        if (process.env.ENABLE_DEMO_SEEDING === 'true') {
            await seedDefaultIdentities(db);
        }

        return { connected: true, db, dbName: MONGODB_DATABASE };
    } catch (err) {
        isConnected = false;
        connectionError = err.message;
        console.warn(`[MongoDB] Database unavailable (${err.message})`);
        return { connected: false, error: err.message };
    }
}

async function getDBStatus() {
    if (!client || !isConnected) {
        // Try connecting
        const res = await connectDB();
        if (!res.connected) {
            return {
                status: 'UNAVAILABLE',
                connected: false,
                details: 'Database Unavailable',
                error: connectionError
            };
        }
    }

    try {
        await db.command({ ping: 1 });
        return {
            status: 'READY',
            connected: true,
            details: 'Database Ready (MongoDB Local)'
        };
    } catch (err) {
        isConnected = false;
        connectionError = err.message;
        return {
            status: 'UNAVAILABLE',
            connected: false,
            details: 'Database Unavailable',
            error: err.message
        };
    }
}

async function seedDefaultIdentities(database) {
    try {
        const usersCol = database.collection('users');

        // Create unique index on normalized email
        await usersCol.createIndex({ email_normalized: 1 }, { unique: true });

        // Dev Identity 1: DeepTrust Owner
        const ownerEmail = 'owner@deeptrust.demo';
        const existingOwner = await usersCol.findOne({ email_normalized: ownerEmail });
        if (!existingOwner) {
            const hashedOwnerPass = await bcrypt.hash('OwnerSecret123!', 10);
            await usersCol.insertOne({
                full_name: 'DeepTrust Owner',
                email: ownerEmail,
                email_normalized: ownerEmail,
                password_hash: hashedOwnerPass,
                role: 'DEEPTRUST_OWNER',
                organization_id: 'DEEPTRUST_PLATFORM',
                organization_name: 'DeepTrust Security Platform',
                status: 'ACTIVE',
                email_verified: false,
                face_enrolled: false,
                mfa_enabled: false,
                created_at: new Date(),
                updated_at: new Date(),
                last_login_at: null
            });
            console.log('[MongoDB Seed] Created DeepTrust Owner account (owner@deeptrust.demo)');
        }

        // Dev Identity 2: Healthcare Security Admin
        const adminEmail = 'admin@healthcare.demo';
        const existingAdmin = await usersCol.findOne({ email_normalized: adminEmail });
        if (!existingAdmin) {
            const hashedAdminPass = await bcrypt.hash('AdminSecret123!', 10);
            await usersCol.insertOne({
                full_name: 'Healthcare Security Admin',
                email: adminEmail,
                email_normalized: adminEmail,
                password_hash: hashedAdminPass,
                role: 'HOSPITAL_ADMIN',
                organization_id: 'HEALTHCARE_ORG_1',
                organization_name: 'Healthcare Organization',
                status: 'ACTIVE',
                email_verified: false,
                face_enrolled: false,
                mfa_enabled: false,
                created_at: new Date(),
                updated_at: new Date(),
                last_login_at: null
            });
            console.log('[MongoDB Seed] Created Hospital Admin account (admin@healthcare.demo)');
        }
    } catch (seedErr) {
        console.warn('[MongoDB Seed] Seeding notice:', seedErr.message);
    }
}

function getDbInstance() {
    return db;
}

module.exports = {
    connectDB,
    getDBStatus,
    getDbInstance
};
