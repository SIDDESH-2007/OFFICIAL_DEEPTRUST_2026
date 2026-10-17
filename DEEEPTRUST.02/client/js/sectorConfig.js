export const SECTOR_CONFIG = {
    banking: {
        key: 'banking',
        label: 'Banking',
        riskWeights: { face: 0.3, voice: 0.3, behavior: 0.2, ip: 0.2 },
        roles: ['Retail Customer', 'Admin', 'Fraud Analyst'],
        threatTypes: ['Account Takeover', 'KYC Deepfake', 'Transaction Fraud'],
        voiceTemplates: {
            high: 'High-risk financial authentication attempt blocked.',
            medium: 'Financial login requires additional verification.'
        },
        protectionPoints: [
            'Account takeover prevention',
            'Deepfake KYC bypass protection',
            'Fraudulent transaction login defense'
        ],
        metrics: {
            card1: { title: 'Blocked Transactions', subtitle: 'Fraudulent transactions blocked', value: 31 },
            card2: { title: 'Fraud Attempts', subtitle: 'High-risk financial attempts', value: 57 },
            card3: { title: 'Suspicious Logins', subtitle: 'Requires analyst review', value: 11 },
            card4: { title: 'Average Risk Score', subtitle: 'Cross-channel login risk', value: 44 }
        },
        defaultClassification: {
            attackType: 'KYC Deepfake',
            confidence: '93%',
            reasons: ['Face texture inconsistency', 'KYC liveness mismatch', 'Document-to-face delta']
        },
        users: [
            {
                email: 'retail@deeptrustbank.com',
                ip: '203.11.22.5',
                device: 'Chrome / Win11',
                risk: 24,
                statusClass: 'low',
                statusLabel: 'Active',
                reasons: ['Trusted device (+0)', 'Known location (+0)', 'Normal behavior (+0)'],
                country: 'UAE',
                state: 'Dubai',
                city: 'Dubai',
                isp: 'Etisalat',
                vpn: 'No',
                browser: 'Chrome 121',
                os: 'Windows 11',
                deviceType: 'Desktop',
                resolution: '1920x1080',
                fingerprint: 'fp-bank-1a2b',
                loginTime: '12:42:10',
                duration: '00:14:22',
                sessionStatus: 'Active',
                lastActivity: '12:56:32',
                previousAttempts: '0',
                deepfakeConfidence: '8%',
                actionTaken: 'Allowed',
                attackType: 'Normal Login',
                behavior: ['Opened dev tools: No', 'Switched tabs frequently: No', 'Clipboard activity: No', 'Sensitive action attempt: No']
            },
            {
                email: 'fraud.analyst@deeptrustbank.com',
                ip: '77.99.40.13',
                device: 'Edge / Win11',
                risk: 87,
                statusClass: 'high',
                statusLabel: 'Blocked',
                reasons: ['Face mismatch (+30)', 'New device (+25)', 'Login time anomaly (+20)', 'Typing deviation (+12)'],
                country: 'DE',
                state: 'Berlin',
                city: 'Berlin',
                isp: 'Vodafone DE',
                vpn: 'Yes',
                browser: 'Edge 121',
                os: 'Windows 11',
                deviceType: 'Desktop',
                resolution: '1366x768',
                fingerprint: 'fp-bank-9z8y',
                loginTime: '12:50:15',
                duration: '00:03:54',
                sessionStatus: 'Blocked',
                lastActivity: '12:54:09',
                previousAttempts: '5',
                deepfakeConfidence: '89%',
                actionTaken: 'Auto-block + voice alert',
                attackType: 'KYC Deepfake',
                behavior: ['Opened dev tools: Yes', 'Switched tabs frequently: Yes', 'Clipboard activity: Yes', 'Sensitive action attempt: Yes']
            }
        ]
    },
    financial: {
        key: 'financial',
        label: 'Financial Services',
        riskWeights: { face: 0.25, voice: 0.2, behavior: 0.35, ip: 0.2 },
        roles: ['Traders', 'High-net-worth Clients', 'Compliance Officer'],
        threatTypes: ['Trading Manipulation', 'Crypto Wallet Access', 'API Abuse'],
        voiceTemplates: {
            high: 'Suspicious trading account authentication blocked.',
            medium: 'Trading platform login requires step-up verification.'
        },
        protectionPoints: [
            'Trading account access protection',
            'Crypto wallet authentication hardening',
            'Loan portal fraud prevention'
        ],
        metrics: {
            card1: { title: 'API Abuse Alerts', subtitle: 'Detected across trading endpoints', value: 19 },
            card2: { title: 'Trading Anomalies', subtitle: 'Behavioral strategy deviations', value: 41 },
            card3: { title: 'Bot Login Attempts', subtitle: 'Automated credential probes', value: 27 },
            card4: { title: 'Average Risk Score', subtitle: 'High-volatility auth risk', value: 52 }
        },
        defaultClassification: {
            attackType: 'API Abuse',
            confidence: '91%',
            reasons: ['Token replay signature', 'Burst traffic spike', 'Unusual endpoint sequence']
        },
        users: [
            {
                email: 'trader.alpha@deeptrustfs.com',
                ip: '185.7.18.90',
                device: 'Safari / macOS',
                risk: 49,
                statusClass: 'medium',
                statusLabel: 'Step-up',
                reasons: ['New device (+20)', 'Off-hours login (+15)', 'Minor behavior drift (+14)'],
                country: 'UK',
                state: 'England',
                city: 'London',
                isp: 'BT Business',
                vpn: 'No',
                browser: 'Safari 17',
                os: 'macOS 14',
                deviceType: 'Laptop',
                resolution: '1728x1117',
                fingerprint: 'fp-fin-c11e',
                loginTime: '13:06:28',
                duration: '00:07:09',
                sessionStatus: 'Step-up',
                lastActivity: '13:13:03',
                previousAttempts: '2',
                deepfakeConfidence: '28%',
                actionTaken: 'Step-up verification',
                attackType: 'Trading Manipulation',
                behavior: ['Opened dev tools: No', 'Switched tabs frequently: Yes', 'Clipboard activity: Yes', 'Sensitive action attempt: No']
            },
            {
                email: 'compliance@deeptrustfs.com',
                ip: '93.44.12.201',
                device: 'Firefox / Win11',
                risk: 73,
                statusClass: 'high',
                statusLabel: 'Blocked',
                reasons: ['API abuse pattern (+32)', 'IP risk (+18)', 'Behavior anomaly (+23)'],
                country: 'FR',
                state: 'Île-de-France',
                city: 'Paris',
                isp: 'Orange',
                vpn: 'Yes',
                browser: 'Firefox 122',
                os: 'Windows 11',
                deviceType: 'Desktop',
                resolution: '1920x1080',
                fingerprint: 'fp-fin-a9d3',
                loginTime: '13:11:42',
                duration: '00:02:31',
                sessionStatus: 'Blocked',
                lastActivity: '13:14:18',
                previousAttempts: '4',
                deepfakeConfidence: '61%',
                actionTaken: 'Auto-block + voice alert',
                attackType: 'API Abuse',
                behavior: ['Opened dev tools: Yes', 'Switched tabs frequently: Yes', 'Clipboard activity: Yes', 'Sensitive action attempt: Yes']
            }
        ]
    },
    healthcare: {
        key: 'healthcare',
        label: 'Healthcare',
        riskWeights: { face: 0.4, voice: 0.2, behavior: 0.2, ip: 0.2 },
        roles: ['Doctors', 'Patients', 'Medical Admin'],
        threatTypes: ['Patient Record Access', 'Prescription Fraud', 'Deepfake Doctor Login'],
        voiceTemplates: {
            high: 'Unauthorized patient data access attempt detected.',
            medium: 'Medical portal access requires additional verification.'
        },
        protectionPoints: [
            'Patient record access protection',
            'Prescription fraud mitigation',
            'Doctor portal login verification'
        ],
        metrics: {
            card1: { title: 'Patient Access Anomalies', subtitle: 'Abnormal EHR access patterns', value: 22 },
            card2: { title: 'Unauthorized Data Access', subtitle: 'Blocked sensitive record requests', value: 33 },
            card3: { title: 'Deepfake Doctor Attempts', subtitle: 'High-confidence spoof detections', value: 14 },
            card4: { title: 'Average Risk Score', subtitle: 'Clinical identity risk baseline', value: 47 }
        },
        defaultClassification: {
            attackType: 'Deepfake Doctor Login',
            confidence: '95%',
            reasons: ['Face contour mismatch', 'Liveness micro-expression failure', 'Hospital VPN mismatch']
        },
        users: [
            {
                email: 'doctor.rashid@deeptrustcare.com',
                ip: '62.44.12.11',
                device: 'Chrome / macOS',
                risk: 38,
                statusClass: 'medium',
                statusLabel: 'Step-up',
                reasons: ['New location (+15)', 'Behavior variance (+12)', 'IP risk (+11)'],
                country: 'UAE',
                state: 'Abu Dhabi',
                city: 'Abu Dhabi',
                isp: 'du',
                vpn: 'No',
                browser: 'Chrome 122',
                os: 'macOS 14',
                deviceType: 'Laptop',
                resolution: '1512x982',
                fingerprint: 'fp-health-1f77',
                loginTime: '13:02:07',
                duration: '00:11:21',
                sessionStatus: 'Step-up',
                lastActivity: '13:13:50',
                previousAttempts: '1',
                deepfakeConfidence: '24%',
                actionTaken: 'Step-up verification',
                attackType: 'Patient Record Access',
                behavior: ['Opened dev tools: No', 'Switched tabs frequently: No', 'Clipboard activity: Yes', 'Sensitive action attempt: No']
            },
            {
                email: 'medical.admin@deeptrustcare.com',
                ip: '141.23.20.144',
                device: 'Edge / Win11',
                risk: 82,
                statusClass: 'high',
                statusLabel: 'Blocked',
                reasons: ['Deepfake doctor signal (+34)', 'Unauthorized data route (+24)', 'Identity mismatch (+24)'],
                country: 'NL',
                state: 'North Holland',
                city: 'Amsterdam',
                isp: 'KPN',
                vpn: 'Yes',
                browser: 'Edge 121',
                os: 'Windows 11',
                deviceType: 'Desktop',
                resolution: '1600x900',
                fingerprint: 'fp-health-7d11',
                loginTime: '13:08:34',
                duration: '00:04:06',
                sessionStatus: 'Blocked',
                lastActivity: '13:12:12',
                previousAttempts: '4',
                deepfakeConfidence: '91%',
                actionTaken: 'Auto-block + voice alert',
                attackType: 'Deepfake Doctor Login',
                behavior: ['Opened dev tools: Yes', 'Switched tabs frequently: Yes', 'Clipboard activity: Yes', 'Sensitive action attempt: Yes']
            }
        ]
    }
};

export const getSectorKeyFromValue = (value) => {
    const normalized = String(value || '').toLowerCase();
    if (normalized.includes('financial')) {
        return 'financial';
    }
    if (normalized.includes('health')) {
        return 'healthcare';
    }
    return 'banking';
};